#include <iostream>
#include <thread>
#include <map>
#include <pcap/pcap.h>
#include "src/atp.h"
using namespace std;
int main(int argc, char **argv)
{
	printf("this file reads the parameters and the role of the node\n");
	ATP *one;
	if (strcmp(argv[1], "2") == 0)
	{
		// switch
		one = new ATP("switch-iface1");
		one->work();
		int socket = one->accept_conn(0, 0, 0);
		char string[50] = {0};
		while (1)
		{
			one->recv(socket, string, 50);
			cout << string << endl;
		}
	}
	else if (strcmp(argv[1], "1") == 0)
	{
		one = new ATP("host1-iface1");
		one->work();
		int socket = one->init_conn(0, 0);
		cout << socket << endl;
		char str[50];
		while(cin>>str)
		one->send(socket, str, sizeof(str));
	}
	else if (strcmp(argv[1], "3") == 0)
	{
		one = new ATP("host2-iface1");
		one->work();
		int socket = one->init_conn(0, 0);
		cout << socket << endl;
		char string[50] = {0};
		while (cin >> string)
		{
			cout << string << endl;
			cout << one->send(socket, string, 50);
		}
	}
	return 0;
}