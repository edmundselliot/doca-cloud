#include "main.h"
#include "app.h"

int main() {
    doca_error_t result;
	struct doca_log_backend *sdk_log;

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

    OffloadApp app = OffloadApp("0000:8a:00.0", "0xf");
    app.init();

    return 0;
}