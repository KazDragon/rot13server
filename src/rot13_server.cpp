#include "connection.hpp"
#include <serverpp/tcp_server.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/algorithm_ext/erase.hpp>
#include <algorithm>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

namespace {

serverpp::byte_storage rot13_encode(serverpp::bytes data)
{
    auto const &encode_byte = [](serverpp::byte datum)
    {
        if (datum >= 'A' && datum <= 'Z')
        {
            return serverpp::byte('A' + (((datum - 'A') + 13) % 26));
        }
        else if (datum >= 'a' && datum <= 'z')
        {
            return serverpp::byte('a' + (((datum - 'a') + 13) % 26));
        }
        else
        {
            return datum;
        }
        
    };

    auto const encoded_data = data | boost::adaptors::transformed(encode_byte);
    return serverpp::byte_storage{encoded_data.begin(), encoded_data.end()};
}

}

namespace rot13 {

class server
{
public:
    server()
      : work_(boost::asio::make_work_guard(io_context_)),
        tcp_server_(
            io_context_, 
            0, 
            [this](auto &&new_socket) 
            { 
                this->new_connection(std::forward<decltype(new_socket)>(new_socket));
            })
    {
        std::cout << "TCP Server started up on port " << tcp_server_.port() << "\n";
    }

    void run()
    {
        io_context_.run();
    }

private:
    void new_connection(serverpp::tcp_socket &&new_socket)
    {
        std::cout << "Accepted new socket\n";

        auto lock = std::unique_lock<std::mutex>{connections_mutex_};
        connections_.emplace_back(new connection(std::move(new_socket)));

        auto &connection = connections_.back();
        lock.unlock();

        connection->async_get_terminal_type(
            [](std::string const &ttype)
            {
                std::cout << "Terminal type = " << ttype << "\n";
            });

        connection->on_window_size_changed(
            [](std::uint16_t width, std::uint16_t height)
            {
                std::cout << "Window size is now " << width << "x" << height << "\n";
            });

        schedule_read(*connection);
    }

    void schedule_read(connection &cnx)
    {
        cnx.async_read(
            [this, &cnx](serverpp::bytes data)
            {
                read_handler(cnx, data);
            },
            [this, &cnx]()
            {
                if (cnx.is_alive())
                {
                    schedule_read(cnx);
                }
                else
                {
                    connection_death_handler(cnx);
                }
            });
    }

    void read_handler(connection &cnx, serverpp::bytes data)
    {
        cnx.write(rot13_encode(data));
    }

    void connection_death_handler(connection &dead_connection)
    {
        std::cout << "Connection died\n";
        std::unique_lock<std::mutex> lock(connections_mutex_);

        const auto is_dead_connection = [&dead_connection](auto const &connection)
        {
            return connection.get() == &dead_connection;
        };

        boost::for_each(
            connections_ | boost::adaptors::filtered(is_dead_connection),
            [](auto &connection)
            {
                connection.reset();
            });

        boost::remove_erase_if(
            connections_,
            [](auto const &connection)
            {
                return !connection;
            });
    }

    void close_all_connections()
    {
        std::unique_lock<std::mutex> lock(connections_mutex_);

        boost::for_each(
            connections_,
            [](auto &connection)
            {
                connection->close();
            });
    }

    boost::asio::io_context io_context_;
    boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type> work_;

    serverpp::tcp_server tcp_server_;

    std::mutex connections_mutex_;
    std::vector<std::unique_ptr<connection>> connections_;
};

}

int main()
{
    auto server = std::unique_ptr<rot13::server>(new rot13::server);

    std::vector<std::thread> threads;
    for (int i = 0; i < std::thread::hardware_concurrency(); ++i)
    {
        threads.emplace_back([&server]{server->run();});
    }

    for (auto &thread : threads)
    {
        thread.join();
    }

    server.reset();
}