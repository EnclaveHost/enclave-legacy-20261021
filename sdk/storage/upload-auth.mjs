// Browser-native implementation stays inside site/ so the unbundled console
// and bundled SDK/CLI use the same signing bytes.
export {uploadMessage,directUploadHeaders,directUploadDigestHeaders} from '../../site/js/core/upload-auth.js';
