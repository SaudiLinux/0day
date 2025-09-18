# 🔒 VulnScanner - Advanced Security Assessment Tool

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/Security-Assessment-critical?style=for-the-badge&logo=security" alt="Security">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

## 🌟 المميزات الرئيسية

تم تصميم **VulnScanner** كأداة متقدمة لإدارة سطح الهجوم واكتشاف الثغرات الأمنية، مع دعم للبيئات المتنوعة وتقليل الإيجابيات الخاطئة.

### ✅ القدرات الأساسية
- **إدارة سطح الهجوم**: مسح شامل للبنية التحتية والتطبيقات
- **اكتشاف الثغرات**: تحديد الثغرات المعروفة والناشئة في الوقت الحقيقي
- **دعم البيئات المتنوعة**: يعمل على Windows، Linux، وmacOS
- **تقليل الإيجابيات الخاطئة**: خوارزميات ذكية لدقة عالية في النتائج
- **عرض الروابط المصابة**: تحديد دقيق للموارد والروابط المعرضة للخطر

### 🔍 التقنيات المتقدمة
- **الذكاء الاصطناعي**: خوارزميات تعلم آلي لاكتشاف التهديدات الجديدة
- **المسح التدريجي**: فحص مستمر وتحديثات في الوقت الحقيقي
- **قاعدة بيانات الثغرات**: تحديثات يومية لقاعدة بيانات CVE
- **تقارير متعددة الصيغ**: JSON، CSV، PDF، HTML
- **واجهة ويب تفاعلية**: لوحة تحكم حديثة ومتجاوبة

## 🚀 التثبيت والاستخدام

### المتطلبات
- Go 1.21 أو أحدث
- امتيازات المسؤول (للمسح الشبكي المتقدم)
- اتصال إنترنت (لتحديثات قاعدة البيانات)

### التثبيت
```bash
# استنساخ المشروع
git clone https://github.com/SayerLinux/VulnScanner.git
cd VulnScanner

# تحميل التبعيات
go mod download

# بناء الأداة
go build -o vulnscanner

# تشغيل الأداة
./vulnscanner --help
```

### الاستخدام السريع
```bash
# مسح شبكة محلية
./vulnscanner scan --target 192.168.1.0/24 --ports 1-1000

# مسح موقع ويب
./vulnscanner scan --target example.com --web-scan

# فتح لوحة التحكم
./vulnscanner dashboard --port 8080

# توليد تقرير PDF
./vulnscanner report --scan-id SCAN-123 --format pdf
```

## 📊 أوامر CLI

### الأمر: scan
```bash
./vulnscanner scan [خيارات]
```

**الخيارات:**
- `--target`: الهدف (IP، نطاق IP، أو نطاق CIDR)
- `--ports`: نطاق المنافذ (مثال: 1-1000 أو 80,443,8080)
- `--timeout`: مهلة الاتصال (ثواني)
- `--threads`: عدد الخيوط المتوازية
- `--web-scan`: تفعيل مسح تطبيقات الويب
- `--aggressive`: وضع المسح العدواني
- `--output`: تنسيق الإخراج (json, csv, pdf, html)

### الأمر: dashboard
```bash
./vulnscanner dashboard [خيارات]
```

**الخيارات:**
- `--port`: منفذ الخادم (افتراضي: 8080)
- `--host`: عنوان المضيف (افتراضي: 0.0.0.0)
- `--auth`: تفعيل المصادقة

### الأمر: report
```bash
./vulnscanner report [خيارات]
```

**الخيارات:**
- `--scan-id`: معرف المسح
- `--format`: تنسيق التقرير (json, csv, pdf, html)
- `--output`: مسار حفظ الملف

## 🎯 أمثلة الاستخدام

### 1. مسح شبكة الشركة
```bash
# مسح شامل لجميع الأجهزة في الشبكة
./vulnscanner scan --target 10.0.0.0/8 --ports 1-65535 --threads 100

# مسح الخوادم الحساسة
./vulnscanner scan --target 10.0.1.100-10.0.1.200 --ports 22,80,443,3389 --aggressive
```

### 2. فحص تطبيقات الويب
```bash
# مسح موقع ويب
./vulnscanner scan --target https://example.com --web-scan --output html

# فحص عدة تطبيقات
./vulnscanner scan --target app1.com,app2.com --web-scan --timeout 30
```

### 3. مراقبة مستمرة
```bash
# مسح دوري كل 24 ساعة
while true; do
    ./vulnscanner scan --target 192.168.1.0/24 --output json
    sleep 86400
done
```

## 📈 لوحة التحكم

الواجهة الويب توفر:
- **لوحة معلومات تفاعلية**: عرض النتائج في الوقت الحقيقي
- **رسوم بيانية**: توزيع الثغرات حسب الخطورة
- **إدارة المهام**: جدولة المسحات وتتبع التقدم
- **تصدير التقارير**: تحميل النتائج بصيغ متعددة
- **المصادقة**: حماية الوصول إلى النتائج الحساسة

### فتح لوحة التحكم
```bash
./vulnscanner dashboard --port 8080 --auth
```

ثم افتح المتصفح على: `http://localhost:8080`

## 🔍 قاعدة بيانات الثغرات

يتضمن الأداة قاعدة بيانات شاملة تحتوي على:
- **CVE Database**: أكثر من 200,000 ثغرة معروفة
- **ExploitDB**: ثغرات تم اختبارها عملياً
- **Zero-day Signatures**: توقيعات للتهديدات الناشئة
- **Custom Signatures**: توقيعات مخصصة للبيئات الخاصة

### تحديث قاعدة البيانات
```bash
# تحديث يدوي
./vulnscanner update --vulndb

# تحديث تلقائي (مفعل افتراضياً)
# يتم التحديث يومياً في الساعة 3 صباحاً
```

## 📋 التقارير والتحليلات

### أنواع التقارير
1. **JSON**: للتكامل مع أدوات أخرى
2. **CSV**: للتحليل في Excel أو أدوات BI
3. **PDF**: لتقارير رسمية قابلة للطباعة
4. **HTML**: لتقارير تفاعلية مع رسوم بيانية

### مكونات التقرير
- **ملخص تنفيذي**: نظرة عامة على المخاطر
- **إحصائيات مفصلة**: عدد الثغرات حسب الخطورة
- **تفاصيل كل ثغرة**: الوصف، الدليل، والتوصيات
- **التوصيات**: خطوات الإصلاح المقترحة
- **تحليل المخاطر**: تقدير الأثر والاحتمالية

## 🔧 التخصيص والتكوين

### ملف التكوين (`config.yaml`)
```yaml
scanner:
  timeout: 10
  threads: 50
  ports: "1-1000"
  
database:
  update_interval: "24h"
  max_age: "30d"
  
reporting:
  default_format: "html"
  include_screenshots: true
  risk_threshold: 5.0
  
ai_detection:
  enabled: true
  confidence_threshold: 0.7
  training_data_days: 90
```

### التوقيعات المخصصة
يمكن إضافة توقيعات ثغرات مخصصة في ملف `custom_signatures.json`:
```json
{
  "signatures": [
    {
      "id": "CUSTOM-001",
      "name": "Custom Application Vulnerability",
      "severity": "High",
      "pattern": "vulnerable_pattern_here",
      "recommendation": "Update to latest version"
    }
  ]
}
```

## 🛡️ الأمان والخصوصية

### إرشادات الأمان
- استخدم الأداة فقط على الأنظمة التي تمتلك صلاحية اختبارها
- احتفظ بالتقارير في مواقع آمنة
- لا تشارك نتائج المسح مع جهات غير مصرح لها
- حدث الأداة بانتظام للحصول على أحدث التوقيعات

### حماية البيانات
- يتم تشفير البيانات الحساسة في التقارير
- لا يتم إرسال أي معلومات إلى خوادم خارجية
- يمكن تشغيل الأداة في وضع عدم الاتصال
- دعم كامل للمسح داخل الشبكات المعزولة

## 🐛 استكشاف الأخطاء وإصلاحها

### المشكلات الشائعة

**1. مشاكل في المسح الشبكي**
```bash
# تأكد من امتيازات المسؤول
sudo ./vulnscanner scan --target 192.168.1.0/24

# تحقق من جدار الحماية
./vulnscanner scan --target example.com --timeout 30
```

**2. أخطاء في قاعدة البيانات**
```bash
# إعادة تهيئة قاعدة البيانات
./vulnscanner init --reset-db

# تحديث قاعدة البيانات يدوياً
./vulnscanner update --force
```

**3. مشاكل في التقارير**
```bash
# التحقق من صلاحيات الكتابة
chmod 755 reports/

# استخدام تنسيق بديل
./vulnscanner report --scan-id SCAN-123 --format json
```

## 📚 الوثائق الإضافية

- [دليل المستخدم الكامل](docs/user-guide.md)
- [وثائق API](docs/api-reference.md)
- [دليل التطوير](docs/development.md)
- [أمثلة الاستخدام](docs/examples.md)

## 🤝 المساهمة

نرحب بالمساهمات! يرجى قراءة [دليل المساهمة](CONTRIBUTING.md) قبل إرسال الطلبات.

### أنواع المساهمات المطلوبة
- 🐛 إصلاح الأخطاء البرمجية
- ✨ ميزات جديدة
- 📖 تحسين الوثائق
- 🌍 الترجمة
- 🔍 توقيعات ثغرات جديدة

## 📞 الدعم والتواصل

- 📧 البريد الإلكتروني: [SayerLinux1@gmail.com](mailto:SayerLinux1@gmail.com)
- 🐙 GitHub Issues: [مشكلات المشروع](https://github.com/SayerLinux/VulnScanner/issues)
- 💬 نقاشات المجتمع: [GitHub Discussions](https://github.com/SayerLinux/VulnScanner/discussions)

## 📄 الترخيص

هذا المشروع مرخص تحت [رخصة MIT](LICENSE).

---

<div align="center">
  <p><strong>تم التطوير بواسطة SayerLinux</strong></p>
  <p>🔒 أداة احترافية لأمن المعلومات وإدارة سطح الهجوم</p>
</div>