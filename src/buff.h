#pragma once
#include <cstring>
#include <mutex>
#include <condition_variable>
#include <vector>
/*head_第一个可读位置，tail_为第一个可写位置
对于write head_==tail_为满
对于read head_==tail_为空
*/
class CircularBuffer
{
public:
    CircularBuffer(int size) : head_(0), tail_(0), empty_(true), full_(false), kBufferSize_(size), buffer_(size, '\0') {}
    // 写入指定长度的数据到缓冲区
    int Write(const char *data, int length, int mod = 0)
    { // 读写不需要互斥，写之间需要，读直接需要互斥
      // FIX 关于满和空的判断，要求length不为0
        if (length <= 0)
            return 0;
        if (length > kBufferSize_)
            length = kBufferSize_;
        // mod=0 能写就写一部分
        // mod=1 要写就全能写,保证包的完整
        std::unique_lock<std::mutex> lock(mutex_); // 获取互斥锁
        if (mod == 0)
        {
            while (full_)
            {
                printf("buff write full\n");
                not_full_.wait(lock);
            }
        }
        else if (mod == 1)
        {
            if (full_)
            {
                return 0;
            }
            else if (head_ <= tail_ && length > kBufferSize_ - (tail_ - head_))
            {
                return 0;
            }
            else if (head_ > tail_ && length > head_ - tail_)
            {
                return 0;
            }
        }
        int i = 0;
        while (i < length)
        {
            if (head_ <= tail_)
            { // 复制到环形缓冲区尾部时需要分段处理
                if (tail_ + length - i >= kBufferSize_)
                {
                    int len = kBufferSize_ - tail_;
                    memcpy(&buffer_[tail_], &data[i], len);
                    tail_ = 0;
                    i += len;
                }
                else
                {
                    int len = length - i;
                    memcpy(&buffer_[tail_], &data[i], len);
                    tail_ += len;
                    i += len;
                }
            }
            else
            { // 要么->tail_ head_->, head_->tail_
                int len = std::min(length - i, head_ - tail_);
                memcpy(&buffer_[tail_], &data[i], len);
                tail_ += len;
                i += len;
                break; // 此处要么缓冲区满 要么所有数据都写入
            }
        }
        empty_ = false;
        full_ = (tail_ == head_);
        not_empty_.notify_all(); // 发送已经不空的条件变量
        return i;
    }
    // 从缓冲区读取指定长度的数据
    int Read(char *data, int length)
    {
        if (length <= 0)
            return 0;

        if (length > kBufferSize_)
            length = kBufferSize_;
        std::unique_lock<std::mutex> lock(mutex_); // 获取互斥锁

        while (empty_)
        {
            printf("buff read empty\n");
            not_empty_.wait(lock);
        }

        int i = 0;
        while (i < length)
        {
            if (tail_ <= head_ && head_ + length - i >= kBufferSize_)
            { // 复制到环形缓冲区尾部时需要分段处理
                int len = kBufferSize_ - head_;
                memcpy(&data[i], &buffer_[head_], len);
                head_ = 0;
                i += len;
            }
            else
            {                                                  // 剩下必然head_->tail_
                int len = std::min(length - i, tail_ - head_); // 计算能够读取的最大长度
                memcpy(&data[i], &buffer_[head_], len);
                head_ += len;
                i += len;
                break;
            }
        }
        full_ = false;
        empty_ = (head_ == tail_);
        not_full_.notify_all(); // 发送已经不满的条件变量
        return i;
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        buffer_.clear();
        head_ = tail_ = 0;
        empty_ = true;

        full_ = false;
    }

private:
    int head_;                          // 缓冲区头部下标
    int tail_;                          // 缓冲区尾部下标
    bool empty_;                        // 缓冲区是否为空
    bool full_;                         // 缓冲区是否已满
    int kBufferSize_;                   // 缓冲区大小
    std::vector<char> buffer_;          // 缓冲区
    std::mutex mutex_;                  // 互斥锁
    std::condition_variable not_full_;  // 条件变量，缓冲区不满
    std::condition_variable not_empty_; // 条件变量，缓冲区非空
};
