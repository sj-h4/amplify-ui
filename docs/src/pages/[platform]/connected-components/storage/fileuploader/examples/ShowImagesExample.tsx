import { FileUploader } from '@aws-amplify/ui-react';

export const ShowImagesExample = () => {
  return (
    <FileUploader
      showImages={false}
      variation="drop"
      acceptedFileTypes={['image/*']}
      accessLevel="public"
      // @ts-ignore // IGNORE
      provider="fast" // IGNORE
    />
  );
};