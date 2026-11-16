#import <AVFoundation/AVFoundation.h>
#import <UIKit/UIKit.h>
#import <dispatch/dispatch.h>

#include "../../src/pairing_qr.h"

#include <huxerui/app.h>
#include <huxerui/ios/platform_registry.h>

#include <utility>

using QrPhotoResult = huxerui::IoResult<UIImage*>;
using QrPhotoCompletion = void (^)(QrPhotoResult);

@interface HUXLocalNetworkQrCapture : NSObject <UIImagePickerControllerDelegate, UINavigationControllerDelegate,
                                                  HUXPlatformCancellation>
- (instancetype)initWithCompletion:(QrPhotoCompletion)completion finished:(void (^)(void))finished;
- (void)presentFrom:(UIViewController*)presenter;
@end

@implementation HUXLocalNetworkQrCapture {
  UIImagePickerController* _picker;
  QrPhotoCompletion _completion;
  void (^_finished)(void);
}

- (instancetype)initWithCompletion:(QrPhotoCompletion)completion finished:(void (^)(void))finished {
  self = [super init];
  if (self) {
    _completion = [completion copy];
    _finished = [finished copy];
    _picker = [[UIImagePickerController alloc] init];
    _picker.sourceType = UIImagePickerControllerSourceTypeCamera;
    _picker.cameraCaptureMode = UIImagePickerControllerCameraCaptureModePhoto;
    _picker.modalPresentationStyle = UIModalPresentationFullScreen;
    _picker.delegate = self;
  }
  return self;
}

- (void)presentFrom:(UIViewController*)presenter {
  [presenter presentViewController:_picker animated:YES completion:nil];
}

- (void)finishWithResult:(QrPhotoResult)result {
  UIImagePickerController* picker = _picker;
  if (!picker) return;
  _picker = nil;
  picker.delegate = nil;
  auto completion = _completion;
  auto finished = _finished;
  _completion = nil;
  _finished = nil;
  // Release the presentation slot before resuming the application task.
  void (^dismissed)(void) = ^{
    finished();
    completion(result);
  };
  if (picker.presentingViewController) [picker dismissViewControllerAnimated:YES completion:dismissed];
  else dismissed();
}

- (void)imagePickerController:(UIImagePickerController*)picker
    didFinishPickingMediaWithInfo:(NSDictionary<UIImagePickerControllerInfoKey, id>*)info {
  if (picker != _picker) return;
  UIImage* image = info[UIImagePickerControllerOriginalImage];
  if (image) [self finishWithResult:QrPhotoResult::Success(image)];
  else [self finishWithResult:QrPhotoResult::Failure({huxerui::IoErrorCode::Io, "The system camera returned no image."})];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController*)picker {
  if (picker == _picker) [self cancel];
}

- (void)cancel {
  [self finishWithResult:QrPhotoResult::Success(nil)];
}

@end

namespace local_network_preview {
namespace {

using namespace huxerui;
constexpr char camera_name[] = "localnetwork/QrCamera";

class QrCamera final {
public:
  explicit QrCamera(UIViewController* owner) : coordinator_(HUXGetPresentationCoordinator(owner)) {}

  Task<QrPhotoResult> Capture() {
    return AwaitCallback<QrPhotoResult>([coordinator = coordinator_](auto completion) {
      id<HUXPlatformCancellation> pending = [coordinator enqueueWithStart:
          ^id<HUXPlatformCancellation>(UIViewController* presenter, void (^finished)(void)) {
            const auto access = [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo];
            if (access == AVAuthorizationStatusDenied || access == AVAuthorizationStatusRestricted) {
              finished();
              completion.Complete(QrPhotoResult::Failure({IoErrorCode::PermissionDenied, "Camera access was denied."}));
              return nil;
            }
            if (![UIImagePickerController isSourceTypeAvailable:UIImagePickerControllerSourceTypeCamera]) {
              finished();
              completion.Complete(QrPhotoResult::Failure({IoErrorCode::Unsupported, "The system camera is unavailable."}));
              return nil;
            }
            auto* capture = [[HUXLocalNetworkQrCapture alloc] initWithCompletion:^(QrPhotoResult result) {
              completion.Complete(std::move(result));
            } finished:finished];
            [capture presentFrom:presenter];
            return capture;
          }
          failure:^(NSError*) {
            completion.Complete(QrPhotoResult::Failure({IoErrorCode::Io, "Could not open the system camera."}));
          }];
      return [pending] {
        dispatch_async(dispatch_get_main_queue(), ^{ [pending cancel]; });
      };
    });
  }

private:
  HUXPresentationCoordinator* coordinator_;
};

Bytes EncodePhoto(UIImage* image) {
  @autoreleasepool {
    NSData* data = UIImageJPEGRepresentation(image, 0.9);
    if (!data.length) return {};
    const auto* first = static_cast<const std::byte*>(data.bytes);
    return Bytes(first, first + data.length);
  }
}

} // namespace

void InstallQrCamera(ApplicationContext& context) {
  ios::WindowPlatformModuleFactory<QrCamera> factory;
  factory.create = [](UiWindow&, UIViewController* owner) { return QrCamera(owner); };
  context.RegisterPlatformModule<QrCamera>(camera_name, std::move(factory));
}

Task<IoResult<bool>> CaptureQrPhoto(File destination) {
  using Result = IoResult<bool>;
  auto camera = OpenPlatformModule<QrCamera>(camera_name);
  auto photo = co_await camera.Capture();
  if (!photo.Succeeded()) co_return Result::Failure(std::move(photo).Error());
  if (!photo.Value()) co_return Result::Success(false);
  auto encoded = co_await RunWorker(EncodePhoto, photo.Value());
  if (encoded.empty() || !co_await destination.WriteBytesAsync(std::move(encoded))) {
    co_return Result::Failure({IoErrorCode::Io, "Could not save the QR photo."});
  }
  co_return Result::Success(true);
}

} // namespace local_network_preview
