# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
LLVM_CONFIG ?= llvm-config
CXX ?= g++

CXXFLAGS := $(shell $(LLVM_CONFIG) --cxxflags) -fPIC -Wall -Wextra -O2
LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags) -shared

TARGET := libRustLivepatchPlugin.so

all: $(TARGET)

$(TARGET): RustLivepatchPlugin.cpp
	$(CXX) $(CXXFLAGS) RustLivepatchPlugin.cpp $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
