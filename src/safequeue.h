#pragma once
#include <iostream>
#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class ThreadSafeQueue
{
private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cond_;

public:
    ThreadSafeQueue() {}

    template <typename... Args>
    void emplace(Args &&...args)
    {

        std::lock_guard<std::mutex> lock(mutex_);
        queue_.emplace(std::forward<Args>(args)...);
        cond_.notify_all();
    }

    void push(const T &value)
    {

        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(value);
        cond_.notify_all();
    }

    bool try_pop(T &value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty())
        {
            return false;
        }
        value = queue_.front();
        queue_.pop();
        return true;
    }

    void wait_and_pop(T &value)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (queue_.empty())
            cond_.wait(lock);
        value = queue_.front();
        queue_.pop();
    }

    bool empty() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
};
