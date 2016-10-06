package net.fornwall.apksigner;
import static org.junit.Assert.assertEquals;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

import org.junit.Test;

import net.fornwall.apksigner.zipio.ZioEntry;
import net.fornwall.apksigner.zipio.ZipInput;

public class ZipInputTest {

	@Test
	public void test() throws Exception {
		String inputFile = getClass().getResource("/simple_test.zip").getFile();
		try (ZipInput zipInput = new ZipInput(inputFile)) {
			assertEquals(2, zipInput.entries.size());
			assertEquals(new HashSet<>(Arrays.asList("answer.txt", "test.txt")), zipInput.entries.keySet());

			assertEquals("42\n", new String(zipInput.entries.get("answer.txt").getData()));
			assertEquals("Hello, world!\n", new String(zipInput.entries.get("test.txt").getData()));

			ZioEntry entry = zipInput.entries.values().iterator().next();
			// Check setTime(), getTime() by using identity transform: setTime(date), new Date(getTime()) == date
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			String inputDate = "2010-12-25 02:59:42";
			Date date = dateFormat.parse(inputDate);

			entry.setTime(date.getTime());
			date = new Date(entry.getTime());

			String testDate = dateFormat.format(date);
			assertEquals(inputDate, testDate);
		}
	}

}
