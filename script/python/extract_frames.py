import cv2
import os
from PIL import Image
import imagehash

# 配置参数
video_path = "input.mkv"        # 输入视频路径
output_dir = "output_frames"    # 输出目录
threshold = 8                   # 敏感度（数值越大保留的帧越多，建议3-8）
jpeg_quality = 95               # 图片质量（1-100）

# 创建输出目录
os.makedirs(output_dir, exist_ok=True)

# 初始化视频捕获
cap = cv2.VideoCapture(video_path)
if not cap.isOpened():
    print("无法打开视频文件")
    exit()

# 读取第一帧
success, prev_frame = cap.read()
if not success:
    print("无法读取视频内容")
    exit()

# 处理首帧
prev_hash = imagehash.average_hash(Image.fromarray(cv2.cvtColor(prev_frame, cv2.COLOR_BGR2RGB)))
cv2.imwrite(os.path.join(output_dir, "frame_0000.jpg"), prev_frame, [cv2.IMWRITE_JPEG_QUALITY, jpeg_quality])
count = 1

# 处理后续帧
while True:
    success, frame = cap.read()
    if not success:
        break
    
    # 计算哈希值
    current_hash = imagehash.average_hash(Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)))
    
    # 哈希差异比较
    if (prev_hash - current_hash) > threshold:
        filename = os.path.join(output_dir, f"frame_{count:04d}.jpg")
        cv2.imwrite(filename, frame, [cv2.IMWRITE_JPEG_QUALITY, jpeg_quality])
        prev_hash = current_hash
        count += 1

cap.release()
print(f"共提取 {count} 个非重复帧到 {output_dir} 目录")
