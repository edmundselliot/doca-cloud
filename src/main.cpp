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

	struct rte_ether_addr vf_mac = {};
	vf_mac.addr_bytes[0] = 0xde;
	vf_mac.addr_bytes[1] = 0xad;
	vf_mac.addr_bytes[2] = 0xbe;
	vf_mac.addr_bytes[3] = 0xef;
	vf_mac.addr_bytes[4] = 0x01;
	vf_mac.addr_bytes[5] = 0x00;

    OffloadApp app = OffloadApp("0000:8a:00.0", "0xf", vf_mac);
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