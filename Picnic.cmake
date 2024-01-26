cmake_minimum_required(VERSION 3.10)

find_library(picnic_lib
    picnic
    PATHS ${picnic_dir}
)
 message( STATUS "Picnic lib: ${picnic_lib}" )
add_library(picnic STATIC IMPORTED) # or SHARED instead of STATIC
set_target_properties(picnic PROPERTIES
  IMPORTED_LOCATION ${picnic_lib}
)

find_library(sha3_lib
    shake
    PATHS ${picnic_dir}/sha3
)
 message( STATUS "Sha3 lib: ${sha3_lib}" )
add_library(sha3 STATIC IMPORTED) # or SHARED instead of STATIC
set_target_properties(sha3 PROPERTIES
  IMPORTED_LOCATION ${sha3_lib}
)

list(APPEND include_dirs ${picnic_dir} ${picnic_dir}/sha3)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -march=native -std=gnu99 -D__LINUX__ -D__X64__") 
