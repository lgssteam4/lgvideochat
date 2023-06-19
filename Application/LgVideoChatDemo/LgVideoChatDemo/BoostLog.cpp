#include "BoostLog.h"

void InitLogging()
{
    // 로그 파일 설정
    logging::add_file_log(
        logging::keywords::file_name = "LgVideoChat.log",
        logging::keywords::rotation_size = 10 * 1024 * 1024                                   /*< rotate files every 10 MiB... >*/
    );

    // 로그 레벨 설정 (여기서는 모든 로그 레벨을 사용)
    logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::trace);
}

