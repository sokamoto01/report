#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define WINDOW_SIZE 65000 // ウィンドウサイズの閾値
//  通常通信のウィンドウサイズ：64240
//  0.9倍：57816
#define COUNT 5 // この値の回数閾値より小さいwindowsizeを送信したセッションを検知

const char *filter = "port 80 and host 127.0.0.1"; // ipアドレスはサーバのものに適宜変更
const char *my_ip = "127.0.0.1";                   //
static int num_detect = 0;                         // 検知件数

FILE *file;
const char *fname = "detect.csv"; // 記録ファイル

//コネクションのリスト構造
struct connection_list
{
  char *s_ip;//送信元ipアドレス
  uint16_t s_port;//送信元ポート番号
  uint8_t WS;//ウィンドウスケーリングの値
  bool FIN_send;//セッション終了でリストを削除するためのフラグ終了処理がサーバから始まるとき使う
  bool FIN_rec;//セッション終了でリストを削除するためのフラグ終了処理がクライアントから始まるとき使う
  int count;//ウィンドウサイズの閾値を下回るパケットを受信した回数
  // uint32_t seq;
  // uint32_t ack;
  struct connection_list *next;
};

static struct connection_list *head = NULL;

//リスト生成を行う 引数(送信元ipアドレス,送信元ポート番号,ウィンドウスケーリング)
struct connection_list *create(char *s_ip, uint16_t s_port, uint8_t WS)
{

  struct connection_list *new;

  new = (struct connection_list *)malloc(sizeof(struct connection_list));

  if (new == NULL)
  {
    fprintf(stderr, "create error\n");
  }

  new->s_ip = s_ip;
  new->s_port = s_port;
  new->WS = WS;
  new->FIN_send = 0;
  new->FIN_rec = 0;
  new->count = 0;

  return new;
}
//リストにウィンドウスケーリングの値を登録する 引数(送信元ipアドレス,送信元ポート番号,ウィンドウスケーリング)
int reg_WS(char *s_ip, uint16_t s_port, uint8_t WS)
{

  struct connection_list *p;
  struct connection_list *new;
  struct connection_list *prev;
  p = head;

  while (p != NULL)
  {
    if (p->s_ip == s_ip && p->s_port == s_port)
    {
      p->WS = WS;
      return 0;
    }
    prev = p;
    p = p->next;
  }

  new = create(s_ip, s_port, WS);

  if (p == head)
  {
    new->next = head;
    head = new;
  }
  else
  {
    prev->next = new;
    new->next = p;
  }

  return 1;
}

//コネクションをリストから削除する 引数(送信元ipアドレス,送信元ポート番号)
int del_connection(char *s_ip, uint16_t s_port)
{

  struct connection_list *p = head;
  struct connection_list *prev;

  if (head == NULL)
  {
    return -1;
  }

  if (p->s_ip == s_ip && p->s_port == s_port)
  {
    head = p->next;
    free(p);
    return 0;
  }

  while (p != NULL)
  {
    if (p->s_ip == s_ip && p->s_port == s_port)
    {
      prev->next = p->next;
      free(p);
      return 0;
    }
    prev = p;
    p = p->next;
  }
  return -1;
}

//引数と一致するリストをreturnする 引数(送信元ipアドレス,送信元ポート番号)
struct connection_list *search(char *s_ip, uint16_t s_port)
{
  struct connection_list *p = head;
  while (p != NULL)
  {
    if (p->s_ip == s_ip && p->s_port == s_port)
    {
      return p;
    }
    p = p->next;
  }
  return NULL;
}

/*struct connection_list * FIN(char* s_ip, uint16_t s_port){
  struct connection_list *p = head;
  while(p != NULL){
    if(p->s_ip == s_ip && p->s_port == s_port){
      p->FIN++;
      return p;
    }
    p = p->next;
  }
  return NULL;
}
*/
//ウィンドウサイズの大きさを判定する関数　引数(パケットの先頭メモリアドレス)
static void
check_win(char *p)
{
  typedef struct
  {
    uint8_t kind;
    uint8_t size;
  } tcp_option_t;

  struct ip *ip;
  ip = (struct ip *)(p + sizeof(struct ether_header));
  struct tcphdr *tcp;
  tcp = (struct tcphdr *)((char *)ip + (ip->ip_hl << 2));

  char *s_ip = inet_ntoa(ip->ip_src);     // 送信元ip
  uint16_t s_port = ntohs(tcp->th_sport); // 送信元ポート番号
  int win;                                // ウィンドウサイズ
  uint8_t WS = 0;                         // ウィンドウスケーリング
  uint8_t tcp_h_size = 0;
  struct connection_list *ptr = NULL;

  char date[64];
  time_t t;
  uint8_t *opt = (uint8_t *)((uint8_t *)tcp + (uint8_t)sizeof(struct tcphdr));

  // printf("s_port %d\n",s_port);

  if ((strcmp(s_ip, my_ip) == 0) && (s_port == 80))
  { // パケットを送ったとき
    // printf("send ");
    if ((ptr = search(inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport))) != NULL)
    {
      if ((tcp->th_flags & 1) == 1)
      { // FINパケットを送ったとき
        if (ptr->FIN_rec == 0)
        {
          ptr->FIN_send = 1;
          // printf("FIN_send =%d",ptr->FIN_send);
          // ptr->seq = tcp->th_seq; //消してもいい
          // ptr->ack = tcp->th_ack;
        }
        return;
      }

      else if ((tcp->th_flags & 17) == 16)
      { // ACKフラグのみのパケットを送ったとき
        // printf("ACK_send = %d",ptr->FIN_send);
        if (ptr->FIN_send == 1)
        {
          del_connection(inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
          // printf("s_end_connect %d\n", ntohs(tcp->th_dport));
        }
        return;
      }

      else if ((tcp->th_flags & 4) == 4)
      { // RSTパケットを送ったとき
        del_connection(inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
        // printf("s_r_end_connect %d\n", ntohs(tcp->th_dport));
      }
      // printf("\n\n");
    }
    return;
  }

  if ((tcp->th_flags & 2) == 2)
  { // SYNパケット
    // printf("SYN seq %u ack %u s_port %d win %d\n", (uint32_t)ntohl(tcp->th_seq), (uint32_t)ntohl(tcp->th_ack), s_port, ntohs(tcp->th_win));
    tcp_h_size = (tcp->th_off * 4) - 20;
    // printf("size %d\n", tcp_h_size);

    for (int i = 0; i < tcp_h_size; i++)
    { // オプションの処理
      tcp_option_t *_opt = (tcp_option_t *)opt;

      if (_opt->kind == 1 /* NOP */)
      {
        ++opt; // NOP is one byte;
        continue;
      }

      if (_opt->kind == 3 /* Window Scaling */)
      {
        WS = (uint8_t) * (opt + sizeof(uint16_t));
        break;
      }
      opt += _opt->size;
    }

    reg_WS(s_ip, s_port, WS);
    // printf("WS_o = %u ",WS);

    if (((win = ntohs(tcp->th_win)) < WINDOW_SIZE) && (ptr = search(s_ip, s_port)) != NULL)
    { // ウィンドウサイズの判定
      ptr->count++;
      if (ptr->count >= COUNT)
      {
        num_detect++;
        t = time(NULL);
        strftime(date, sizeof(date), "%Y/%m/%d %a %H:%M:%S", localtime(&t));
        printf("%d [%s][notice] detect small window size: \'%s\' is suspected as Slow Read DoS attack!\n", num_detect, date, s_ip);
        // printf("%d [%s][notice] detect small window size: \'%s\' is suspected as Slow Read DoS attack!(windowsize: %d byte)\n", num_detect, date, s_ip, win);
        //  printf("SYN seq %u ack %u s_port %d \n",(uint32_t)ntohl(tcp->th_seq), (uint32_t)ntohl(tcp->th_ack), s_port);
        printf("src_port:%d\n\n", s_port);

        if ((file = fopen(fname, "a")) == NULL)
        {
          printf("%sファイルが開けません\n", fname);
          del_connection(s_ip, s_port);
          return;
        }
        fprintf(file, "%d,%s,%d\n", num_detect, s_ip, s_port);
        fclose(file);

        del_connection(s_ip, s_port);
        return;
      }
    }
  }
  else
  {
    if ((ptr = search(s_ip, s_port)) != NULL)
    {
      WS = ptr->WS;
      win = (ntohs(tcp->th_win) << (WS));
      // printf("seq %u ack %u s_port %d win %d\n", (uint32_t)ntohl(tcp->th_seq), (uint32_t)ntohl(tcp->th_ack), s_port, win);

      if ((tcp->th_flags & 4) == 4)
      { // RSTパケットを受け取ったとき
        del_connection(s_ip, s_port);
        // printf("r_end_connect %d\n", s_port);
        return;
      }

      else if (win < WINDOW_SIZE)
      { // ウィンドウサイズの判定
        ptr->count++;
        if (ptr->count >= COUNT)
        {
          num_detect++;
          t = time(NULL);
          strftime(date, sizeof(date), "%Y/%m/%d %a %H:%M:%S", localtime(&t));
          printf("%d [%s][notice] detect small window size: \'%s\' is suspected as Slow Read DoS attack!\n", num_detect, date, s_ip);
          // printf("%d [%s][notice] detect small window size: \'%s\' is suspected as Slow Read DoS attack!(windowsize: %d byte)\n", num_detect, date, s_ip, win);
          //  printf("WS %d win_f %d win %d\n",WS,ntohs(tcp->th_win),win);
          //  printf("seq %u ack %u s_port %d\n",(uint32_t)ntohl(tcp->th_seq), (uint32_t)ntohl(tcp->th_ack), s_port);
          printf("src_port:%d\n\n", s_port);

          if ((file = fopen(fname, "a")) == NULL)
          {
            printf("%sファイルが開けません\n", fname);
            del_connection(s_ip, s_port);
            return;
          }
          fprintf(file, "%d,%s,%d\n", num_detect, s_ip, s_port);
          fclose(file);

          del_connection(s_ip, s_port);
          return;
        }
      }

      if ((tcp->th_flags & 17) == 16)
      { // ACKflagのみのパケットを受け取ったとき
        // printf("ACK");
        if (ptr->FIN_rec == 1)
        {
          del_connection(s_ip, s_port);
          // printf("end_connect %d\n", s_port);
        }
        return;
      }
      else if ((tcp->th_flags & 1) == 1 && (ptr->FIN_send == 0))
      { // FINパケットを受け取ったとき
        ptr->FIN_rec = 1;
        // printf("FIN_rec = %d",ptr->FIN_rec);
      }
      // printf("\n\n");
    }
  }
}

//実行時インターフェイスが指定されないときに使い方を表示する
static void
usage(char *prog)
{

  fprintf(stderr, "Usage: %s <device>n", prog);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  pcap_t *handle;
  const unsigned char *packet;
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;
  struct bpf_program fp;
  bpf_u_int32 net;
  // int cnt = 0;

  if ((dev = argv[1]) == NULL)
    usage(argv[0]);

  /* 受信用のデバイスを開く */
  if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %sn", dev, errbuf);
    exit(EXIT_FAILURE);
  }
  /* イーサネットのみ */
  if (pcap_datalink(handle) != DLT_EN10MB)
  {
    fprintf(stderr, "Device not support: %sn", dev);
    exit(EXIT_FAILURE);
  }

  // port80かつ任意のwebサーバへのパケットのみ受信するフィルターの設定をおこなう
  if (pcap_compile(handle, &fp, filter, 0, net) == -1)
  {
    fprintf(stderr, "Couldn't parse filter: %sn", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "Couldn't install filter: %sn", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if ((file = fopen(fname, "w")) == NULL)
  {
    printf("%sファイルが開けません\n", fname);
    return -1;
  }
  fprintf(file, "num,ip_src,port_src\n");
  fclose(file);

  /* ループでパケットを受信 */
  while (1)
  {
    if ((packet = pcap_next(handle, &header)) == NULL)
      continue;
    // printf("%d observating\n", cnt);

    /* イーサネットヘッダーとIPヘッダーの合計サイズに満たなければ無視 */
    if (header.len < sizeof(struct ether_header) + sizeof(struct ip))
      continue;

    check_win((char *)(packet));
    // cnt++;
  }

  /* ここに到達することはない */
  pcap_close(handle);
  return 0;
}
