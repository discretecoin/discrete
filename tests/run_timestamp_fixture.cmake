# Allocate a fresh retained data directory for every invocation.
if(NOT DEFINED PROGRAM OR NOT DEFINED DATA_ROOT)
  message(FATAL_ERROR "PROGRAM and DATA_ROOT are required")
endif()
string(TIMESTAMP run_time "%Y%m%dT%H%M%S" UTC)
string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef run_suffix)
set(run_directory "${DATA_ROOT}/${run_time}-${run_suffix}")
message(STATUS "Timestamp fixture data: ${run_directory}")
execute_process(COMMAND "${PROGRAM}" --data-dir "${run_directory}"
  RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Timestamp fixture failed: ${result}")
endif()
