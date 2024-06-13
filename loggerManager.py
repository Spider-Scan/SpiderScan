import logging
import os


class ColorHandler(logging.StreamHandler):
    GRAY8 = "38;5;8"
    GRAY7 = "38;5;7"
    ORANGE = "33"
    RED = "31"
    WHITE = "0"
    PURPLE = "35"
    BLUE = "34"

    def emit(self, record):
        try:
            msg = self.format(record)
            level_color_map = {
                logging.DEBUG: self.BLUE,
                logging.INFO: self.GRAY7,
                logging.WARNING: self.ORANGE,
                logging.ERROR: self.RED,
                logging.CRITICAL: self.PURPLE

            }

            csi = f"{chr(27)}["
            color = level_color_map.get(record.levelno, self.WHITE)

            self.stream.write(f"{csi}{color}m{msg}{csi}m\n")
            self.flush()
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)


class LoggerManager:
    def __init__(self, log_name, log_path, asctime=True, overwrite=True):
        self.log_name = log_name
        self.log_path = log_path
        self.logger = self._setup_logger(asctime, overwrite)

    def _setup_logger(self, asctime, overwrite):
        logger_ = logging.getLogger(self.log_name)
        logger_.setLevel(logging.DEBUG)
        if asctime:
            # pipeline logger
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        else:
            formatter = logging.Formatter('%(levelname)s - %(name)s - %(message)s')

        # create log file
        os.makedirs(os.path.join(self.log_path, 'log'), exist_ok=True)
        if overwrite:

            with open(os.path.join(self.log_path, 'log', f"{self.log_name}.log"), 'w'):
                pass
        else:
            with open(os.path.join(self.log_path, 'log', f"{self.log_name}.log"), 'a'):
                pass

        for handler in logger_.handlers[:]:
            handler.close()
            logger_.removeHandler(handler)
        file_handler = logging.FileHandler(os.path.join(self.log_path, 'log', f'{self.log_name}.log'))
        file_handler.setFormatter(formatter)
        logger_.addHandler(file_handler)

        console_handler = ColorHandler()
        console_handler.setFormatter(formatter)
        logger_.addHandler(console_handler)
        return logger_

    def info(self, text):
        self.logger.info(text)

    def warning(self, text):
        self.logger.warning(text)

    def error(self, text):
        self.logger.error(text)

    def critical(self, text):
        self.logger.critical(text)
