#include "main.h"
#include "app.h"

DOCA_LOG_REGISTER(MAIN);

int main(int argc, char *argv[]) {
    doca_error_t result;
    struct doca_log_backend *sdk_log;
    struct input_cfg_t input_cfg = {};

    // Register a logger backend
    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        return EXIT_FAILURE;

    // Register a logger backend for internal SDK errors and warnings
    result = doca_log_backend_create_with_file_sdk(stdout, &sdk_log);
    if (result != DOCA_SUCCESS)
        return EXIT_FAILURE;

    result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
    if (result != DOCA_SUCCESS)
        return EXIT_FAILURE;

    if (argc != 2) {
        DOCA_LOG_ERR("Usage: %s <config file>", argv[0]);
        return EXIT_FAILURE;
    }
    result = parse_input_cfg(argv[1], &input_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse input config file: %s", doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    OffloadApp app = OffloadApp(&input_cfg);
    result = app.init();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to initialize offload app: %s", doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    result = app.run();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to run offload app: %s", doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}