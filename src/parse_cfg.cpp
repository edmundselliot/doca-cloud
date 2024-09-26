#include "main.h"

DOCA_LOG_REGISTER(PARSE_CFG);

doca_error_t parse_input_cfg(std::string filename, struct input_cfg_t *cfg) {
    DOCA_LOG_INFO("Parsing input config file %s", filename.c_str());

    return DOCA_SUCCESS;
}
