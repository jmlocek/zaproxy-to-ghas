import {DefaultArtifactClient} from '@actions/artifact'
const artifact = new DefaultArtifactClient()


async function uploadSarifArtifact(filename: string): Promise<void> {
  const artifactName = 'ZAProxy-sarif-report';
  const files = [filename]; // Files to upload, relative or absolute paths
  const options = {
    retentionDays: 10, // Optional: specify retention period
  };

  try {
    const { id, size } = await artifact.uploadArtifact(artifactName, files, '.');
    console.log(`Artifact uploaded successfully: ID=${id}, Size=${size} bytes`);
  } catch (error) {
    console.error('Failed to upload artifact:', error);
    throw error;
  }
}

export default uploadSarifArtifact;