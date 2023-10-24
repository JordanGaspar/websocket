cmake_minimum_required(VERSION 3.27)

project(Pieces LANGUAGES C CXX)

add_library(Pieces SHARED src/pieces.cpp include/pieces/pieces.hpp)

add_executable(Main src/main.cpp src/pieces.cpp include/pieces/pieces.hpp)
target_link_libraries(Main PUBLIC ssl crypto)
set_property(TARGET Main PROPERTY CXX_STANDARD 23)
target_include_directories(Main PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/pieces)
set_target_properties(Main PROPERTIES PUBLIC_HEADER "include/pieces/pieces.hpp")

set_property(TARGET Pieces PROPERTY CXX_STANDARD 23)

target_include_directories(Pieces PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/pieces)

set_target_properties(Pieces PROPERTIES PUBLIC_HEADER "include/pieces/pieces.hpp")

find_package(Boost REQUIRED)
target_link_libraries(Pieces PUBLIC Boost::boost)

install(TARGETS Pieces 
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include/pieces)