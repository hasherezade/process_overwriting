cmake_minimum_required (VERSION 3.10)

# replace "project_template" by your own project name:
project ( process_overwriting )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
#put your sources here
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	process_manip.h
	overwrite.h
)

set (rsrc
	process_manip.cpp
	overwrite.cpp
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )


# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
