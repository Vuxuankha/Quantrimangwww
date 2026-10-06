"""Pin GUI and service to a common data directory; never copies/overwrites DB."""
import argparse
import json
from pathlib import Path

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir',required=True,help='Existing data root containing database/, not database/ itself')
    args=parser.parse_args()
    root=Path(args.data_dir).expanduser().resolve()
    if not root.is_dir():parser.error('Thư mục dữ liệu phải tồn tại trước.')
    config=Path(__file__).resolve().parent/'data_location.json'
    config.write_text(json.dumps({'data_dir':str(root)},ensure_ascii=False,indent=2),encoding='utf-8')
    print('Đã ghi:',config)
    print('Dừng GUI và service rồi khởi động lại. Nếu dùng EXE, chép cùng file JSON cạnh EXE.')
    print('NETWORK_AUTOMATION_DATA_DIR nếu đã đặt sẽ ưu tiên hơn file JSON. Không tự chép dữ liệu.')
