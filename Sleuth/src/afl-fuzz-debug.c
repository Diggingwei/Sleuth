#include "afl-fuzz.h"
#include <inttypes.h>


void write_target_log(afl_state_t *afl) {

    if (!afl->target_debug_log) {

        afl->target_debug_log = alloc_printf("%s/target_debug", afl->out_dir);
        afl->target_debug_fd = fopen(afl->target_debug_log, "w");

    }

    u64 current_ms = get_cur_time() - afl->start_time;

    fprintf(afl->target_debug_fd, "[%02lld:%02lld:%02lld] now we found %d all targets %d all edges\n", 
            current_ms / 1000 /3600, (current_ms / 1000 /60) % 60, (current_ms / 1000) % 60,
            afl->current_targets_triggered, afl->current_targets_reached);
}

void write_check_log(afl_state_t *afl, u32 num, u16 address, u32 len) {

    if (!afl->queue_debug_log) {

        afl->queue_debug_log = alloc_printf("%s/queue_debug", afl->out_dir);
        afl->queue_debug_fd = fopen(afl->queue_debug_log, "w");

    }

    char str[17] = {'\0'};

    for (int i = 15; i >= 0 ; i--){

        if (address & (1 << i)){
            strcat(str, "1");
        } else {
            strcat(str, "0");
        }

    }

    u64 current_ms = get_cur_time() - afl->start_time;

    fprintf(afl->queue_debug_fd, "[%02lld:%02lld:%02lld] now we get %d entry at address %s in all %d entry\n", 
            current_ms / 1000 /3600, (current_ms / 1000 /60) % 60, (current_ms / 1000) % 60,
            num, str, len);    

}

void write_level_log(afl_state_t *afl, u16 level_score, u16 level_num){

    

    if (!afl->level_debug_log) {
        afl->level_debug_log = alloc_printf("%s/level_debug", afl->out_dir);
        afl->level_debug_fd = fopen(afl->level_debug_log, "w");
    }

    u64 current_ms = get_cur_time() - afl->start_time;

    fprintf(afl->level_debug_fd, "[%02lld:%02lld:%02lld] now the highest level is %d in the %d number of levels\n",
            current_ms /1000 /3600, (current_ms /1000 /60) % 60, (current_ms / 1000) % 60,
            level_score, level_num);

}

void write_bb_log(afl_state_t *afl, u32 idx_level[], u16 size){
    
    if(!afl->basicblock_debug_log) {
        afl->basicblock_debug_log = alloc_printf("%s/bb_debug", afl->out_dir);
        afl->basicblock_debug_fd = fopen(afl->basicblock_debug_log, "w");
    }
    
    char output[2000];
    char output_2[2000];

    for (u16 i = 0; i < size; i++){

        char buffer[40];
        u16 idx = (idx_level[i] >> 16) & 0xFFFF;
        u16 level = idx_level[i] & 0xFFFF;
        sprintf(buffer, "%hu:%hu ", idx, level);
        strcat(output, buffer);
    }

    u64 current_ms = get_cur_time() - afl->start_time;

    fprintf(afl->basicblock_debug_fd, "[%02lld:%02lld:%02lld] now the queue of basicblock is %s\n",
            current_ms /1000 /3600, (current_ms /1000 /60) % 60, (current_ms / 1000) % 60,
            output);
}

void write_pos(afl_state_t *afl, u32 pos_idx[], u32 pos_now){
    
    if(!afl->pos_debug_log){
        afl->pos_debug_log = alloc_printf("%s/pos_debug", afl->out_dir);
        afl->pos_debug_fd = fopen(afl->pos_debug_log, "w");
    }

    size_t buffer_size = fuzzed_pos_cnt * (10 + 2) + 1;
    char* out = malloc(buffer_size);
    if(!out){
        return NULL;
    }

    out[0] = '\0';

    for(size_t i = 0; i < fuzzed_pos_cnt; i++){
        char buffer[10 + 3];
        int written = snprintf(buffer, sizeof(buffer), "%" PRIu32, pos_idx[i]);
        if (i != 0){
            strcat(out, "@@");
        }
        strcat(out, buffer);
    }

    //char buffer_2[10 + 1];
    //int written = snprintf(buffer_2, sizeof(buffer_2), "%" PRIu32, pos_now);

    u64 current_ms = get_cur_time() - afl->start_time;

    fprintf(afl->pos_debug_fd, "[%02lld:%02lld:%02lld] now the hash is %u, now the queue of union hash is %s\n",
            current_ms /1000 /3600, (current_ms /1000 /60) % 60, (current_ms / 1000) % 60,
            pos_now, out);

}

void write_log(afl_state_t *afl, u8 new_cap_idx, u8 new_pos_idx, u8 exploration_state, u32 switch_num, u32 pos_num){

    if(!afl->switch_debug_log){
        afl->switch_debug_log = alloc_printf("%s/switch_debug", afl->out_dir);
        afl->switch_debug_fd = fopen(afl->switch_debug_log, "w");
    }

    u64 current_ms = get_cur_time() - afl->start_time;

    afl->last_log_time = get_cur_time();

    fprintf(afl->switch_debug_fd, "[%02lld:%02lld:%02lld] now the new_cap is %d, now the new_pos is %d, the switch is %d, now the new cap hash is %u, now the new pos hash is %u, the current exec time is %d, the last check time is %d, the current switch time is %d, the last switch time is %d, the all switch number is %d, the all position number is %d\n",
            current_ms /1000 /3600, (current_ms /1000 /60) % 60, (current_ms / 1000) % 60,
            new_cap_idx, new_pos_idx, exploration_state, now_cap_hash, now_pos_hash, afl->fsrv.total_execs, afl->last_check_exec, get_cur_time(), afl->last_check_time, switch_num, pos_num);

}

void write_switch_log(afl_state_t *afl, u32 depth_num, u32 breadth_num){

    if(!afl->count_debug_log){
        afl->count_debug_log = alloc_printf("%s/switch_count_debug", afl->out_dir);
        afl->count_debug_fd = fopen(afl->count_debug_log, "w");
    }

    u64 current_ms = get_cur_time() - afl->start_time;

    fprintf(afl->count_debug_fd, "[%02lld:%02lld:%02lld] now the total depth exploration number is %d, now the total breadth number is %d\n", current_ms /1000 /3600, (current_ms /1000 /60) % 60, (current_ms / 1000) % 60, depth_num, breadth_num);

}
