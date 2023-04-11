#include "../src/buff.h"
#include <iostream>
#include <thread>
using namespace std;
CircularBuffer buff(5);
void readthread()
{
    char out[10] = {0};
    while (true)
    {
        out[buff.Read(out, 10)] = '\0';
        cout << out;
    }
}
int main()
{
    thread(readthread).detach();
    char in[] ="1111111111111111111111111999233";
    int ans=0;
    while(ans<sizeof(in)){
        int temp=buff.Write(in+ans, sizeof(in)-ans);
        //sleep(0.5);
        ans+=temp;
    }
    return 0;
}