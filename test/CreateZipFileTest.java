import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import kellinwood.zipio.ZioEntry;
import kellinwood.zipio.ZipInput;
import kellinwood.zipio.ZipOutput;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CreateZipFileTest {

	private final File testDir = new File(getClass().getResource("/simple_test.zip").getFile()).getParentFile();
	private final File outputFile = new File(testDir, "test_create.zip");
	private ZipOutput zipOutput;

	@Before
	public void setUp() throws Exception {
		zipOutput = new ZipOutput(new FileOutputStream(outputFile));
	}

	@After
	public void tearDown() throws Exception {
		outputFile.delete();
	}

	static void assertZipEntryEquals(ZipInput input, String entryName, String expected) throws IOException {
		assertEquals(expected, new String(input.entries.get(entryName).getData()));
	}

	static void assertZipEntryEquals(ZipFile input, String entryName, String expected) throws IOException {
		ZipEntry entry = input.getEntry(entryName);
		Assert.assertNotNull("The entry '" + entryName + "' does not exist");
		int size = (int) entry.getSize();
		byte[] buffer = new byte[size];
		Assert.assertEquals(size, input.getInputStream(entry).read(buffer));
		assertEquals(expected, new String(buffer, StandardCharsets.UTF_8));
	}

	@Test
	public void createZipTest() throws Exception {
		ZioEntry entry = new ZioEntry("B.txt");
		OutputStream entryOut = entry.getOutputStream();
		String bContentText = "The answer to the ultimate question of life, the universe, and everything is 42.";
		entryOut.write(bContentText.getBytes());
		zipOutput.write(entry);

		entry = new ZioEntry("A.txt");
		entry.setCompression(0);
		entryOut = entry.getOutputStream();
		String aContentText = "The name of the computer used to calculate the answer to the ultimate question is \"Earth\".";
		entryOut.write(aContentText.getBytes());
		zipOutput.write(entry);

		zipOutput.close();

		// Verify the result with java.util.zip:
		try (ZipFile zipInput = new ZipFile(outputFile)) {
			assertZipEntryEquals(zipInput, "A.txt", aContentText);
			assertZipEntryEquals(zipInput, "B.txt", bContentText);
		}

		// Verify the result with zio:
		try (ZipInput zipInput = new ZipInput(outputFile.getAbsolutePath())) {
			assertZipEntryEquals(zipInput, "A.txt", aContentText);
			assertZipEntryEquals(zipInput, "B.txt", bContentText);
		}
	}

	@Test
	public void createZipTestSingleFile() throws Exception {
		ZioEntry entry = new ZioEntry("simple_test.txt");
		entry.getOutputStream().write("hello, world".getBytes(StandardCharsets.UTF_8));
		zipOutput.write(entry);

		// entry = new ZioEntry("A.txt");
		// String aContentText =
		// "The name of the computer used to calculate the answer to the ultimate question is \"Earth\".";
		// entry.getOutputStream().write(aContentText.getBytes());
		// zipOutput.write(entry);

		zipOutput.close();

		// Verify the result with java.util.zip:
		try (ZipFile zipInput = new ZipFile(outputFile)) {
			assertZipEntryEquals(zipInput, "simple_test.txt", "hello, world");
		}
		// Verify the result with zio:
		try (ZipInput zipInput = new ZipInput(outputFile.getAbsolutePath())) {
			assertZipEntryEquals(zipInput, "simple_test.txt", "hello, world");
		}
	}

	@Test
	public void mergeZipTest() throws Exception {
		String zipInputPath = getClass().getResource("/simple_test.zip").getFile();
		try (ZipInput zipInput = new ZipInput(zipInputPath)) {
			ZioEntry testEntry = zipInput.entries.get("test.txt");
			// Change the name of the file, so it becomes to test_new.txt in the output
			testEntry.setName("test_new.txt");

			String aContentText = "The name of the computer used to calculate the answer to the ultimate question is \"Earth\".";
			String bContentText = "The answer to the ultimate question of life, the universe, and everything is 42.";

			ZioEntry entry = new ZioEntry("A.txt");
			entry.setCompression(0);
			OutputStream entryOut = entry.getOutputStream();
			entryOut.write(aContentText.getBytes());
			zipOutput.write(entry);

			entry = new ZioEntry("B.txt");
			entryOut = entry.getOutputStream();
			entryOut.write(bContentText.getBytes());
			zipOutput.write(entry);

			for (ZioEntry e : zipInput.entries.values())
				zipOutput.write(e);
			zipOutput.close();

			// Verify the result with java.util.zip:
			try (ZipFile mergedInput = new ZipFile(outputFile)) {
				assertZipEntryEquals(mergedInput, "A.txt", aContentText);
				assertZipEntryEquals(mergedInput, "B.txt", bContentText);
				assertZipEntryEquals(mergedInput, "answer.txt", "42\n");
				assertZipEntryEquals(mergedInput, "test_new.txt", "Hello, world!\n");
			}
			// Verify the result with zio:
			try (ZipInput mergedInput = new ZipInput(outputFile.getAbsolutePath())) {
				assertZipEntryEquals(mergedInput, "A.txt", aContentText);
				assertZipEntryEquals(mergedInput, "B.txt", bContentText);
				assertZipEntryEquals(mergedInput, "answer.txt", "42\n");
				assertZipEntryEquals(mergedInput, "test_new.txt", "Hello, world!\n");
			}
		}
	}
}