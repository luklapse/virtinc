#include <iostream>
#include <cstring>
#include <fstream>
#include "src/atp.h"
using namespace std;
int main(int argc, char **argv)
{
	printf("this file reads the parameters and the role of the node\n");
	ATP *one;
	if (strcmp(argv[1], "switch") == 0)
	{
		// switch
		ofstream outfile;
		outfile.open("out.txt", ios::out);
		one = new ATP("switch-iface1");
		one->work();
		int socket = one->accept_conn(0, 0, 0);
		cout << "socket " << socket << endl;
		char string[5000] = {0};
		while (true)
		{
			int ans = one->recv(socket, string, sizeof(string));
			string[ans] = '\0';
			outfile << string << flush;
		}
	}
	else if (strcmp(argv[1], "host1") == 0)
	{
		ifstream infile;
		infile.open("in.txt", ios::in);
		if (!infile.is_open())
		{
			cout << "open file error\n";
		}
		one = new ATP("host1-iface1");
		one->work();
		int socket = one->init_conn(0, 0);
		cout << "socket " << socket << endl;
		std::string str((std::istreambuf_iterator<char>(infile)), (std::istreambuf_iterator<char>()));
		one->send(socket, str.data(), str.size());
		while (cin >> str)
		{
			one->send(socket, str.data(), str.size());
		}
	}
	else if (strcmp(argv[1], "host2") == 0)
	{
		one = new ATP("host2-iface1");
		one->work();
		int socket = one->init_conn(0, 0);
		cout << "socket " << socket << endl;
		char str[50] = {0};
		while (cin >> str)
			one->send(socket, str, strlen(str));
	}
	return 0;
}