# WHS-pcap-programming
pcap 라이브러리를 이용한 sniffing 프로그램 개발


이 프로그램은 libpcap 라이브러리를 활용하므로 아래 명령어로 설치합니다.

```
sudo apt-get install libpcap-dev          # linux
brew install libpcap                      # mac-os
```

git clone을 수행한 후 디렉토리로 이동하여 아래 명령어로 컴파일 및 실행합니다.

```
gcc -o tcp_sniff tcp_sniff.c -lpcap
sudo ./tcp_sniff
```

실행시 반드시 sudo를 붙여줘야 합니다.
