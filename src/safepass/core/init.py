from safepass.config.settings import DATA_DIR

def initialize_directories() -> None:

    directories = [DATA_DIR]

    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise e