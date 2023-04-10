#pragma once
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <cstring>
template <typename T>
class SimVector    // 1.保证申请的内存是干净的
{                  // 2.capacity_>size 即left不为0，且内存的增长是缓慢的
protected:         // 3.只保证值类型，需要更强大模板请使用vector
                   // 4.不提供对已经申请的做任何操作,
    int capacity_; 
    int size_;
    T *data_ = nullptr;

public:
    SimVector(int capacity = 2048) : capacity_(capacity), size_(0)
    {
        if (capacity_ != 0)
        { // printf("SimVector 构造\n");
            data_ = (T *)calloc(capacity_, sizeof(T));
        }
    }
    SimVector(const SimVector &) = delete; // unique_
    SimVector(SimVector &&) = delete;
    SimVector &operator=(const SimVector &) = delete;
    SimVector &operator=(SimVector &&) = delete;
    T operator[](int i) const
    {
        assert(i >= 0 && i <= size_);
        return *(data_ + i);
    }
    T *begin()
    {
        return data_;
    }
    T *end()
    {
        return data_ + size_;
    }
    void shift_to(int size){  //强制重置大小到size
        T *tmp = (T *)realloc(data_, (size) * sizeof(T));
        if (tmp)
            data_ = tmp;
        else
        {   
            assert(tmp);
        }
        capacity_=size;
    }
    void reserve(int size) //capacity_，容器至少比size大，并非是size
    {                  
        if (capacity_ > size)
            return;
        T *tmp = (T *)realloc(data_, (size + 4096) * sizeof(T));
        if (tmp)
            data_ = tmp;
        else
        {   
            assert(tmp);
        }
        memset(data_ + size_, 0, (size + 4096 - capacity_) * sizeof(T));
        capacity_ = size + 4096; 
    }
    bool resize(int size) //size_  如果扩容会改变capacity_
    {
        if (size >= 0)
            size_ = size;
        if (capacity_ > size_)
            return false;
        reserve(size);
        return true;
    }
    int leftsize() const
    {
        return capacity_ - size_;
    }
    int size() const
    {
        return size_;
    }
    int capacity() const
    {
        return capacity_;
    }
    T *data() // 返回基指针
    {
        return data_;
    }
    ~SimVector()
    {
        if (data_)
            free(data_);
    }
};

class Buff : public SimVector<char>
{
private:
    int peek_;  //当作游标使用,方便缓冲区操作
public:
    Buff():SimVector<char>(){peek_ = 0;}
    Buff(int len) : SimVector<char>(len) { peek_ = 0; }
    void PeekAdd(int len) { peek_ += len; }
    char *Peek() { return data_ + peek_; }
    bool TryEarsePeek(int mark = 20480)
    {
        if (capacity_ > mark)
        {   
            memcpy(data_, Peek(), size_ - peek_);
            peek_ = 0;
            size_ = size_ - peek_;
            bzero(end(), capacity_ - size_);
            return true;
        }
        return false;
    }
    int peekleft(){
       return size_ - peek_;
    }
    void clear()
    {
        size_ = 0;
        peek_ = 0;
        bzero(data_, capacity_);
    }
    void append (const char * str){
        while(*str!='\0')
        {
            data_[size_++]=*str;
            str++;
        }
    }
    void append(const std::string &str)
    {
        append(str.data(), str.length());
    }

    void append(const void *data, int len)
    {
        assert(data);
        append(static_cast<const char *>(data), len);
    }

    void append(const char *str, int len)
    {
        assert(str);
        //EnsureWriteable(len);
        if (leftsize() < len)
        {
            reserve(capacity_+len);
        }
        memcpy(end(),str,len);
        resize(size_+len);
    }

};