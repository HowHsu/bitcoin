add_executable(txgraph-replay txgraph_replay.cpp)
target_link_libraries(txgraph-replay
  PRIVATE
    core_interface
    bitcoin_node
)
