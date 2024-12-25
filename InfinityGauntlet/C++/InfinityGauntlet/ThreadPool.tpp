// This content should be placed in ThreadPool.tpp, which is included at the end of ThreadPool.hpp

template <typename F, typename... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    using return_type = typename std::result_of<F(Args...)>::type;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );

    std::future<return_type> res = task->get_future();
    {
        std::unique_lock<std::mutex> lock(queueMutex);

        if (stopFlag) {
            std::promise<return_type> promise;
            if constexpr (std::is_same<return_type, void>::value) {
                promise.set_value();
            } else {
                promise.set_value(return_type{});
            }
            return promise.get_future();
        }

        tasks.emplace([task]() { (*task)(); });
    }
    condition.notify_one();
    return res;
}
