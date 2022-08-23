set(SOURCES
        sqlite3.c
        esp32.c
        shox96_0_2.c
)

set(INCLUDES
        .
        include
)

idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS ${INCLUDES}
    PRIV_INCLUDE_DIRS private_include
    PRIV_REQUIRES spi_flash vfs
)

set_source_files_properties(
    ${SOURCES}
    PROPERTIES COMPILE_FLAGS "-fstrict-volatile-bitfields -Wno-unused-function -Wno-discarded-qualifiers -Wno-unused-but-set-variable -Wno-unused-value -Wno-unused-variable -Wno-cast-function-type -DNDEBUG"
)
