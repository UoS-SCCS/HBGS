cmake_minimum_required(VERSION 3.10)

project(generate_public_key C CXX)

set(Sources
    Generate_public_key.cpp
)

if (HBGS_PARAMETER_SET_TEST1)
    add_executable(generate_public_key_129 ${Sources})
    target_include_directories(generate_public_key_129 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(generate_public_key_129 PRIVATE project_options project_warnings stdc++ hbgs_lib_129_1 ${ossl_libs} picnic sha3)
elseif (HBGS_PARAMETER_SET_TEST2)
    add_executable(generate_public_key_255 ${Sources})
    target_include_directories(generate_public_key_255 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(generate_public_key_255 PRIVATE project_options project_warnings stdc++ hbgs_lib_255_1 ${ossl_libs} picnic sha3)
elseif (HBGS_PARAMETER_SET_TEST3)
    add_executable(generate_public_key_129 ${Sources})
    target_include_directories(generate_public_key_129 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(generate_public_key_129 PRIVATE project_options project_warnings stdc++ hbgs_lib_129_2 ${ossl_libs} picnic sha3)
elseif (HBGS_PARAMETER_SET_TEST4)
    add_executable(generate_public_key_255 ${Sources})
    target_include_directories(generate_public_key_255 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(generate_public_key_255 PRIVATE project_options project_warnings stdc++ hbgs_lib_255_2 ${ossl_libs} picnic sha3)
elseif (HBGS_PARAMETER_SET_TEST5)
    add_executable(generate_public_key_129 ${Sources})
    target_include_directories(generate_public_key_129 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(generate_public_key_129 PRIVATE project_options project_warnings stdc++ hbgs_lib_129_4 ${ossl_libs} picnic sha3)
elseif (HBGS_PARAMETER_SET_TEST6)
    add_executable(generate_public_key_255 ${Sources})
    target_include_directories(generate_public_key_255 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(generate_public_key_255 PRIVATE project_options project_warnings stdc++ hbgs_lib_255_4 ${ossl_libs} picnic sha3)
elseif (HBGS_PARAMETER_SET_TEST7)
    add_executable(generate_public_key_129 ${Sources})
    target_include_directories(generate_public_key_129 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(generate_public_key_129 PRIVATE project_options project_warnings stdc++ hbgs_lib_129_6 ${ossl_libs} picnic sha3)
elseif (HBGS_PARAMETER_SET_TEST8)
    add_executable(generate_public_key_255 ${Sources})
    target_include_directories(generate_public_key_255 SYSTEM PRIVATE ${include_dirs})
    target_link_libraries(generate_public_key_255 PRIVATE project_options project_warnings stdc++ hbgs_lib_255_6 ${ossl_libs} picnic sha3)
else()
    message( FATAL_ERROR "No HBGS parameter set selected, CMake will exit." )
endif()
