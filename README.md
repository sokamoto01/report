このプログラムはWebサーバが受信するパケットを監視し，設定した閾値を下回るTCPウィンドウサイズを送出するTCPセッションを検知するプログラムである．

[使用方法]

このプログラムではパケットをキャプチャするためにpcap.hを用いるのでインストールが必要
以下の文でインストールする．
$ sudo apt-get install libpcap-dev

ウィンドウサイズの閾値は15行目のWINDOW_SIZEで指定する．
18行目のCOUNTは閾値より小さいウィンドウサイズのパケットを何回受信することで検知を行うかを指定できる．
20行目，21行目のIPアドレスはサーバのIPアドレスに変更する．
25行目の記録ファイルには検知を行ったとき，送信元IPアドレス，ポート番号のデータが記録される．

[コンパイル]

gcc detect_slow_win.c -lpcap 

コンパイルするときは-lpcapをつける


[実行]

./ a.out <eth0> 

<>カッコ内はネットワークインタフェイスを入力する．
<>カッコは必要なし
