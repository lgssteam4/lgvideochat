#include "BoostLog.h"

void InitLogging()
{
    // �α� ���� ����
    logging::add_file_log(
        logging::keywords::file_name = "LgVideoChat.log",
        logging::keywords::rotation_size = 10 * 1024 * 1024                                   /*< rotate files every 10 MiB... >*/
    );

    // �α� ���� ���� (���⼭�� ��� �α� ������ ���)
    logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::trace);
}

