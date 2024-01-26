# Based on:
#
# https://github.com/lefticus/cpp_starter_project/blob/master/CMakeLists.txt
#

cmake_minimum_required(VERSION 3.13)

# Set the project name to your project name
project(hbgs_impl CXX C)

#set(code_dir $ENV{HOME}/Code)
#set(utils_dir ${code_dir}/Utilities)
set(hbgs_dir ${CMAKE_CURRENT_SOURCE_DIR})
set(picnic_dir ${hbgs_dir}/HBGS_picnic)

include(${hbgs_dir}/Cmake-options/StandardProjectSettings.cmake)

# Link this 'library' to set the c++ standard / compile-time options requested
add_library(project_options INTERFACE)
target_compile_features(project_options INTERFACE cxx_std_17)

# Link this 'library' to use the warnings specified in CompilerWarnings.cmake
add_library(project_warnings INTERFACE)

# standard compiler warnings
include(${hbgs_dir}/Cmake-options/CompilerWarnings.cmake)
set_project_warnings(project_warnings)

# sanitizer options if supported by compiler
include(${hbgs_dir}/Cmake-options/Sanitizers.cmake)
enable_sanitizers(project_options)

# allow for static analysis options
include(${hbgs_dir}/Cmake-options/StaticAnalysers.cmake)

# Debugging option to print varaibles
#    e.g. cmake_print_variables(<variable>)
include(CMakePrintHelpers)

option(BUILD_SHARED_LIBS "Enable compilation of shared libraries" OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LIBRARY_OUTPUT_PATH  ${CMAKE_SOURCE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin) 
set(include_dirs ${CMAKE_SOURCE_DIR}/Include ${CMAKE_SOURCE_DIR}/HBGS_picnic)

include(${hbgs_dir}/Picnic.cmake)

set(Lib_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Hbgs_issuer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Picnic_mpc_functions.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Clock_utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Io_utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Lowmc32.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Lowmc64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Hash2_64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_node_address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Merkle_tree.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mfors_tree.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Group_authpaths.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_node_address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_seeds_and_tapes.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_signature_utils.cpp
#    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_lowmc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_lowmc64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_switch.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_hash1.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_hash2.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_working_data.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_tree_hash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_base_authpath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_top_authpath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_mfors_authpath.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_mfors_full_paths.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Common/Mpc_sign_mfors.cpp
)

option(HBGS_PARAMETER_SET_TEST1 "HBGS parameter set for test1 (129,10,32,1,16,35,560)" ON)
option(HBGS_PARAMETER_SET_TEST2 "HBGS parameter set for test2 (255,10,64,1,16,70,1120)" OFF)
option(HBGS_PARAMETER_SET_TEST3 "HBGS parameter set for test3 (129,10,32,2,16,35,560)" OFF)
option(HBGS_PARAMETER_SET_TEST4 "HBGS parameter set for test4 (255,10,64,2,16,70,1120)" OFF)
option(HBGS_PARAMETER_SET_TEST5 "HBGS parameter set for test5 (129,10,32,4,16,35,560)" OFF)
option(HBGS_PARAMETER_SET_TEST6 "HBGS parameter set for test6 (255,10,64,4,16,70,1120)" OFF)
option(HBGS_PARAMETER_SET_TEST7 "HBGS parameter set for test7 (129,10,32,6,16,35,560)" OFF)
option(HBGS_PARAMETER_SET_TEST8 "HBGS parameter set for test8 (255,10,64,6,16,70,1120)" OFF)


#    Picnic3_L1 = 1, Picnic3_L5 = 2, Picnic3_L1t = 3, Picnic3_L5t = 4. See picnic.h and picnic.c
if (HBGS_PARAMETER_SET_TEST1)
    add_compile_definitions(HBGS_N=129 HBGS_QA=10 HBGS_DS=32 HBGS_H=1 HBGS_D=16 HBGS_K=35 PICNIC_PS=1 HBGS_MPC_R=560 HBGS_MPC_O=35)
    message(STATUS "HBGS parameter set for test1 selected")
    add_library(hbgs_lib_129_1 STATIC ${Lib_sources})
    target_include_directories(hbgs_lib_129_1 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(hbgs_lib_129_1 PRIVATE project_options project_warnings)
elseif (HBGS_PARAMETER_SET_TEST2)
    add_compile_definitions(HBGS_N=255 HBGS_QA=10 HBGS_DS=64 HBGS_H=1 HBGS_D=16 HBGS_K=70 PICNIC_PS=2 HBGS_MPC_R=1120 HBGS_MPC_O=70)
    message(STATUS "HBGS parameter set for test2 selected")
    add_library(hbgs_lib_255_1 STATIC ${Lib_sources})
    target_include_directories(hbgs_lib_255_1 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(hbgs_lib_255_1 PRIVATE project_options project_warnings)
elseif (HBGS_PARAMETER_SET_TEST3)
    add_compile_definitions(HBGS_N=129 HBGS_QA=10 HBGS_DS=32 HBGS_H=2 HBGS_D=16 HBGS_K=35 PICNIC_PS=1 HBGS_MPC_R=560 HBGS_MPC_O=35)
    message(STATUS "HBGS parameter set for test3 selected")
    add_library(hbgs_lib_129_2 STATIC ${Lib_sources})
    target_include_directories(hbgs_lib_129_2 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(hbgs_lib_129_2 PRIVATE project_options project_warnings)
elseif (HBGS_PARAMETER_SET_TEST4)
    add_compile_definitions(HBGS_N=255 HBGS_QA=10 HBGS_DS=64 HBGS_H=2 HBGS_D=16 HBGS_K=70 PICNIC_PS=2 HBGS_MPC_R=1120 HBGS_MPC_O=70)
    message(STATUS "HBGS parameter set for test4 selected")
    add_library(hbgs_lib_255_2 STATIC ${Lib_sources})
    target_include_directories(hbgs_lib_255_2 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(hbgs_lib_255_2 PRIVATE project_options project_warnings)
elseif (HBGS_PARAMETER_SET_TEST5)
    add_compile_definitions(HBGS_N=129 HBGS_QA=10 HBGS_DS=32 HBGS_H=4 HBGS_D=16 HBGS_K=35 PICNIC_PS=1 HBGS_MPC_R=560 HBGS_MPC_O=35)
    message(STATUS "HBGS parameter set for test5 selected")
    add_library(hbgs_lib_129_4 STATIC ${Lib_sources})
    target_include_directories(hbgs_lib_129_4 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(hbgs_lib_129_4 PRIVATE project_options project_warnings)
elseif (HBGS_PARAMETER_SET_TEST6)
    add_compile_definitions(HBGS_N=255 HBGS_QA=10 HBGS_DS=64 HBGS_H=4 HBGS_D=16 HBGS_K=70 PICNIC_PS=2 HBGS_MPC_R=1120 HBGS_MPC_O=70)
    message(STATUS "HBGS parameter set for test6 selected")
    add_library(hbgs_lib_255_4 STATIC ${Lib_sources})
    target_include_directories(hbgs_lib_255_4 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(hbgs_lib_255_4 PRIVATE project_options project_warnings)
elseif (HBGS_PARAMETER_SET_TEST7)
    add_compile_definitions(HBGS_N=129 HBGS_QA=10 HBGS_DS=32 HBGS_H=6 HBGS_D=16 HBGS_K=35 PICNIC_PS=1 HBGS_MPC_R=560 HBGS_MPC_O=35)
    message(STATUS "HBGS parameter set for test7 selected")
    add_library(hbgs_lib_129_6 STATIC ${Lib_sources})
    target_include_directories(hbgs_lib_129_6 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(hbgs_lib_129_6 PRIVATE project_options project_warnings)
elseif (HBGS_PARAMETER_SET_TEST8)
    add_compile_definitions(HBGS_N=255 HBGS_QA=10 HBGS_DS=64 HBGS_H=6 HBGS_D=16 HBGS_K=70 PICNIC_PS=2 HBGS_MPC_R=1120 HBGS_MPC_O=70)
    message(STATUS "HBGS parameter set for test8 selected")
    add_library(hbgs_lib_255_6 STATIC ${Lib_sources})
    target_include_directories(hbgs_lib_255_6 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(hbgs_lib_255_6 PRIVATE project_options project_warnings)
else()
    message( FATAL_ERROR "Failed to correctly select an HBGS parameter set, CMake will exit." )
endif()


# set these for profiing - there must be a better way
#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
#SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
#SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")

add_subdirectory(Generate_public_key)
add_subdirectory(Generate_credential)
add_subdirectory(Hbgs_group_sign)
