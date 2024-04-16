

message(INFO "<MS>")
message(INFO "<MS> ArduinoBearSSL >>")
message(INFO "<MS>")
message(INFO "<MS> CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")


set(ArduinoBearSSL_SRCS src/ArduinoBearSSL.cpp)
set(ArduinoBearSSL_INCL ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(ArduinoBearSSL_REQU 
    arduino 
    )

idf_component_register(
    INCLUDE_DIRS ${ArduinoBearSSL_INCL} 
    SRCS ${ArduinoBearSSL_SRCS}
    REQUIRES ${ArduinoBearSSL_REQU}
    )

message(INFO "<MS>")
message(INFO "<MS> ArduinoBearSSL <<")
message(INFO "<MS>")
