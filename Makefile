# ── usb_proxy Makefile ────────────────────────────────────────────────────
# 使い方:
#   make            通常ビルド (Release)
#   make debug      デバッグビルド
#   make clean      成果物削除
#   make install    /usr/local/bin にインストール
#   make run VID=0x04a9 PID=0x3218          透過プロキシ実行
#   make fuzz VID=0x04a9 PID=0x3218         ファジング実行
#   make fuzz VID=0x04a9 PID=0x3218 SEED=42 シード固定ファジング

TARGET  := usb_proxy

# ── ソース・ヘッダ ─────────────────────────────────────────────────────────
SRCS    := main.cpp proxy.cpp libgreat.cpp moondancer.cpp
HDRS    := ptp.hpp fuzzer.hpp proxy.hpp libgreat.hpp moondancer.hpp
OBJS    := $(SRCS:.cpp=.o)

# ── コンパイラ・フラグ ─────────────────────────────────────────────────────
CXX     := g++
CXXSTD  := -std=c++20

# libusb-1.0 (pkg-config で自動取得)
LIBUSB_CFLAGS := $(shell pkg-config --cflags libusb-1.0)
LIBUSB_LIBS   := $(shell pkg-config --libs   libusb-1.0)

WARN    := -Wall -Wextra -Wno-unused-parameter
INC     := -I. $(LIBUSB_CFLAGS)
LIBS    := $(LIBUSB_LIBS) -lpthread

# Release / Debug フラグ
CXXFLAGS_RELEASE := -O3 -march=native -DNDEBUG
CXXFLAGS_DEBUG   := -O0 -g3 -fsanitize=address,undefined

# デフォルトは Release
CXXFLAGS ?= $(CXXFLAGS_RELEASE)

# ── ターゲット ─────────────────────────────────────────────────────────────
.PHONY: all debug clean install run fuzz

all: $(TARGET)

debug: CXXFLAGS = $(CXXFLAGS_DEBUG)
debug: LIBS    += -fsanitize=address,undefined
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXSTD) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo ">>> Built: $@"

# ── 汎用コンパイルルール ───────────────────────────────────────────────────
# ヘッダが変更されたときも再コンパイルされるよう、すべての .hpp に依存させる
%.o: %.cpp $(HDRS)
	$(CXX) $(CXXSTD) $(CXXFLAGS) $(WARN) $(INC) -c -o $@ $<

# ── clean ──────────────────────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(TARGET)
	@echo ">>> Cleaned"

# ── install ────────────────────────────────────────────────────────────────
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
	@echo ">>> Installed to /usr/local/bin/$(TARGET)"

# ── 実行ショートカット ─────────────────────────────────────────────────────
# 例: make run VID=0x04a9 PID=0x3218
run: $(TARGET)
ifndef VID
	$(error VID が未指定です。例: make run VID=0x04a9 PID=0x3218)
endif
ifndef PID
	$(error PID が未指定です。例: make run VID=0x04a9 PID=0x3218)
endif
	sudo ./$(TARGET) --vid $(VID) --pid $(PID) --log session.jsonl

# ファジングモード
# 例: make fuzz VID=0x04a9 PID=0x3218 SEED=42
fuzz: $(TARGET)
ifndef VID
	$(error VID が未指定です。例: make fuzz VID=0x04a9 PID=0x3218)
endif
ifndef PID
	$(error PID が未指定です。例: make fuzz VID=0x04a9 PID=0x3218)
endif
	sudo ./$(TARGET) --vid $(VID) --pid $(PID) --fuzz \
		$(if $(SEED),--seed $(SEED),) \
		--log fuzz_$(VID)_$(PID).jsonl