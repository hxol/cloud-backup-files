from PIL import Image
import os

# 配置参数
image_folder = "output_frames"  # 图片目录
output_pdf = "output.pdf"       # 输出PDF文件名
target_width = 1200             # 图片统一宽度（推荐平板阅读尺寸：800-1200）
dpi = 150                       # 输出质量（推荐150-300）

# 获取图片列表
images = []
for filename in sorted(os.listdir(image_folder)):
    if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        img_path = os.path.join(image_folder, filename)
        try:
            img = Image.open(img_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            images.append(img)
        except Exception as e:
            print(f"跳过无效图片 {filename}: {str(e)}")

# 调整图片尺寸
resized_images = []
for img in images:
    w_percent = target_width / float(img.size[0])
    h_size = int(float(img.size[1]) * float(w_percent))
    resized_img = img.resize((target_width, h_size), Image.LANCZOS)
    resized_images.append(resized_img)

# 生成PDF
if resized_images:
    resized_images[0].save(
        output_pdf,
        "PDF",
        resolution=dpi,
        save_all=True,
        append_images=resized_images[1:]
    )
    print(f"PDF已生成：{output_pdf}")
else:
    print("没有找到有效图片")
