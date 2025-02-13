import {DefaultArtifactClient} from '@actions/artifact'
const artifact = new DefaultArtifactClient()


async function uploadSarifArtifact(filename: string): Promise<void> {
  const randomSuffix = Math.floor(10000 + Math.random() * 90000).toString(); 
  const artifactName = `ZAProxy-sarif-report-${randomSuffix}`; // Append random number to artifact name (few artefact pushed in the same workflow)
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