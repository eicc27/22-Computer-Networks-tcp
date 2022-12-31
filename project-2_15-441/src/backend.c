/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))


/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0) {
  }
  result = after(sock->window.last_ack_received, seq);
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  switch (flags) {
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }
      break;
    }
    case SYN_FLAG_MASK:{
      break;
    }
    case SYN_FLAG_MASK|ACK_FLAG_MASK:{
      break;
    }
    default: {
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;

      // No extension.
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);

      seq = get_seq(hdr);

      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
      }
    }
  }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
cmu_tcp_header_t check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  hdr.hlen=0;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    /*TIMEOUT状态，等待三秒，如果有输入则进入到NO_WAIT，否则直接结束(整个check_for_data函数无操作)*/
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after 3 seconds.
      if (poll(&ack_fd, 1, 3000) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      /*MSG_DONTWAIT为非阻塞接受 MSG_PEEK两个参数貌似是为了此次接受完的数据不会删除，下次接受的数据开头和本次一样*/
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  /*当传来的数据大小 大于 tcp头的大小时，说明有payload(真正的有效数据/负载)传输过来*/
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    /*将通过UDP发过来的数据包全部接收，包含header和payload部分*/
    while (buf_size < plen) {
      /*每次从缓存区读出一些数据，直到读完*/
      /*如何保证UDP发送的数据包是顺序正确且未丢失的?*/
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return hdr;
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }

      data_offset += payload_len;
    }
  }
}


void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);
    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}

/*超时重发，最多重新发五次，每次重传在第1,3,7,15,31秒，如果对方有回应则返回0,否则返回1*/
int retransmit(cmu_socket_t *sock, cmu_tcp_header_t *hdr) {
  int flag;
  uint16_t adv_window;
  switch (sock->type) {
    case TCP_INITIATOR:
      flag = SYN_FLAG_MASK;
      adv_window = 0;
      break;
    case TCP_LISTENER:
      flag = SYN_FLAG_MASK | ACK_FLAG_MASK;
      adv_window = MAX_BUF_SIZE;
      break;
    default:
      break;
  }
  uint8_t *packet;
  socklen_t conn_len = sizeof(sock->conn);
  packet = create_packet(sock->my_port, ntohs(sock->conn.sin_port),
                         sock->window.next_ack_expected - 1,
                         sock->window.next_seq_expected,
                         sizeof(cmu_tcp_header_t), sizeof(cmu_tcp_header_t),
                         flag, adv_window, 0, NULL, NULL, 0);
  struct pollfd ack_fd;
  int second = 1;
  while (second <= 16) {
    ack_fd.fd = sock->socket;
    ack_fd.events = POLLIN;
    if (poll(&ack_fd, 1, second * 1000) > 0) {
      recvfrom(sock->socket, hdr, sizeof(cmu_tcp_header_t),
               MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
               &conn_len);
      return 0;
    }
    perror("retran");
    sendto(sock->socket, packet, sizeof(cmu_tcp_header_t), 0,
           (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
    second = second * 2;
  }
  if (poll(&ack_fd, 1, second * 1000) > 0) {
    recvfrom(sock->socket, hdr, sizeof(cmu_tcp_header_t),
             MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
             &conn_len);
    return 0;
  }
  return 1;
}
/**
 * Initiator handshake 
*/
void tcp_handshake_client(cmu_socket_t *sock) {
  srand((unsigned)time(NULL));
  uint8_t *packet;
  cmu_tcp_header_t header;
  uint32_t seq, ack;
  switch (sock->tcp_state) {
    case TCP_CLOSED: { /* first time */
      seq = rand();    // seq应该是一个随机数,rand()可能越界
      /* client
       * 发送SYN，create_packet中SYN_FLAG_MASK代表flag位被设置为SYN，client请求与server进行同步
       */
      packet = create_packet(sock->my_port, ntohs(sock->conn.sin_port), seq, 0,
                             sizeof(cmu_tcp_header_t), sizeof(cmu_tcp_header_t),
                             SYN_FLAG_MASK, 0, 0, NULL, NULL, 0);
      sendto(sock->socket, packet, sizeof(cmu_tcp_header_t), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      free(packet);
      /*发送完第一个SYN包，发起第一次握手，client进入等待server回应(等待server发起第二次握手)状态*/
      sock->tcp_state = TCP_SYN_SEND;
      sock->window.last_ack_received = seq;
      sock->window.last_seq_received = 0;
      sock->window.next_ack_expected = seq + 1;
      sock->window.next_seq_expected = 0;
      break;
    }
    case TCP_SYN_SEND: {
      /*超时重发五次*/
      if (retransmit(sock, &header) != 0) {
        sock->tcp_state = TCP_CLOSED;
      };
      /*确认服务端发送的flag标志被置为1,说明服务端正在确认同步,接收到的ack需要和预期的ack相同的判断,否则关闭链接，并未要求实现client超时重传*/
      if ((get_flags(&header)) == (SYN_FLAG_MASK | ACK_FLAG_MASK) &&
          get_ack(&header) == sock->window.next_ack_expected) {
        seq = get_ack(&header);
        ack = get_seq(&header) + 1;

        sock->window.advertised_window = get_advertised_window(&header);
        packet =
            create_packet(sock->my_port, ntohs(sock->conn.sin_port), seq, ack,
                          sizeof(cmu_tcp_header_t), sizeof(cmu_tcp_header_t),
                          ACK_FLAG_MASK, MAX_BUF_SIZE, 0, NULL, NULL, 0);
        sendto(sock->socket, packet, sizeof(cmu_tcp_header_t), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        free(packet);
        sock->tcp_state = TCP_ESTABLISHED;
        sock->window.last_ack_received = ack;
        sock->window.last_seq_received = seq;
      } else {
        sock->tcp_state = TCP_ERROR;
      }
      break;
    }
    default:
      break;
  }
}

/**
 * Listener handshake 
*/
void tcp_handshake_server(cmu_socket_t *sock) {
  srand((unsigned)time(NULL));
  uint8_t *packet;
  cmu_tcp_header_t header;

  switch (sock->tcp_state) {
    case TCP_CLOSED:
      sock->tcp_state = TCP_LISTEN;
      break;
    case TCP_LISTEN: { /* first time */

      /* server堵塞直到有SYN到达 */
      header = check_for_data(sock, NO_FLAG);
      /*只要flag里的SYN标志位为1,就说明SYN packer 有效，若SYN packet
       * 无效，直接忽略，重新监听*/
      if ((get_flags(&header) & SYN_FLAG_MASK) == SYN_FLAG_MASK) {
        /*计算即将从server发出的ack值*/
        uint32_t ack = get_seq(&header) + 1;
        /*随机生成server的seq值*/
        uint32_t seq = 20;  // rand() % MAXSEQ;
        /* server发出一个SYN和ACK均有效的包，告知client最大可接受的缓存区大小 */
        packet = create_packet(
            sock->my_port, ntohs(sock->conn.sin_port), seq, ack,
            sizeof(cmu_tcp_header_t), sizeof(cmu_tcp_header_t),
            (SYN_FLAG_MASK | ACK_FLAG_MASK), MAX_BUF_SIZE, 0, NULL, NULL, 0);
        sendto(sock->socket, packet, sizeof(cmu_tcp_header_t), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        free(packet);
        /*发送包就已经发起第二次握手，进入等待client发起第三次握手*/
        sock->tcp_state = TCP_SYN_RCVD;
        sock->window.last_ack_received = 0;
        sock->window.last_seq_received = get_seq(&header);
        sock->window.next_ack_expected = seq + 1;
        sock->window.next_seq_expected = ack;
      }
      break;
    }
    case TCP_SYN_RCVD: { /* after recv */
      /*如果没有收到client发过来的ACK包，就要重新发SYN，ACK包，最多重新发五次，每次重传在第1,3,7,15,31秒*/
      if (retransmit(sock, &header) != 0) {
        sock->tcp_state = TCP_LISTEN;
      };

      /**/
      int flag = ((get_flags(&header) & ACK_FLAG_MASK) == ACK_FLAG_MASK);
      uint32_t ack = get_seq(&header);
      uint32_t seq = get_ack(&header);
      sock->window.advertised_window = get_advertised_window(&header);
      if (flag && get_ack(&header) == sock->window.next_ack_expected &&
          get_seq(&header) == sock->window.next_seq_expected) {
        sock->tcp_state = TCP_ESTABLISHED;
        sock->window.last_ack_received = ack;
        sock->window.last_seq_received = seq;
      } else {
        sock->tcp_state = TCP_LISTEN;
      }
    }
    default:
      break;
  }
}

/**
 * If handshake success,return 0 ,else return 1;
 */
int tcp_handshake(cmu_socket_t *sock) {
  sock->tcp_state = TCP_CLOSED;
  while (sock->tcp_state != TCP_ESTABLISHED && sock->tcp_state != TCP_ERROR) {
    switch (sock->type) {
      case TCP_INITIATOR:
        tcp_handshake_client(sock);
        break;
      case TCP_LISTENER:
        tcp_handshake_server(sock);
        break;
      default:
        break;
    }
  }

  if (sock->tcp_state == TCP_ESTABLISHED) {
    return 0;
  } else {
    return 1;
  }
}
