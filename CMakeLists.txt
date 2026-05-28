cmake_minimum_required(VERSION 3.16)
project(usb_proxy CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

# ヘッダ・ソースともプロジェクトルートに配置
include_directories(. ${LIBUSB_INCLUDE_DIRS})

add_executable(usb_proxy
    main.cpp
    proxy.cpp
    libgreat.cpp
    moondancer.cpp
)
target_link_libraries(usb_proxy ${LIBUSB_LIBRARIES} pthread)
target_compile_options(usb_proxy PRIVATE -Wall -Wextra)