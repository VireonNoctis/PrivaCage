package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivaCageDesignTest {
    @Test
    fun recognizesSectionHeadingsIgnoringCaseAndSurroundingWhitespace() {
        assertEquals(
            "DNS PRIVACY",
            PrivaCageDesign.sectionHeading("  dns privacy  ")
        )
        assertEquals(
            "ENCRYPTED DEVICE SYNC",
            PrivaCageDesign.sectionHeading("\nEncrypted Device Sync\n")
        )
        assertEquals(
            "APP PRIVACY REVIEW & AI AUTOMATIONS",
            PrivaCageDesign.sectionHeading(" app privacy review & ai automations ")
        )
        assertEquals(
            "AI PRIVACY AUTOMATIONS",
            PrivaCageDesign.sectionHeading("AI privacy automations")
        )
        assertEquals(
            "APP POLICY REVIEW QUEUE",
            PrivaCageDesign.sectionHeading("app policy review queue")
        )
        assertEquals("LEGAL & PRIVACY", PrivaCageDesign.sectionHeading("legal & privacy"))
        assertNull(PrivaCageDesign.sectionHeading("DNS privacy options"))
        assertNull(PrivaCageDesign.sectionHeading(""))
        assertNull(PrivaCageDesign.sectionHeading(null))
    }

    @Test
    fun mapsSectionsToCompactQuickNavigationLabels() {
        assertEquals("DEVICE", PrivaCageDesign.navigationLabel("ANDROID PRIVACY CONTROLS"))
        assertEquals("SNAPSHOT", PrivaCageDesign.navigationLabel("DEVICE PRIVACY SNAPSHOT (LOCAL ONLY)"))
        assertEquals("HARDENING", PrivaCageDesign.navigationLabel("PRIVACY HARDENING"))
        assertEquals("DNS", PrivaCageDesign.navigationLabel("DNS PRIVACY"))
        assertEquals("ROUTE", PrivaCageDesign.navigationLabel("DNS ROUTE DIAGNOSTICS"))
        assertEquals("AUDIT", PrivaCageDesign.navigationLabel("PRIVACY AUDIT EXPORT"))
        assertEquals("SYNC", PrivaCageDesign.navigationLabel("ENCRYPTED DEVICE SYNC"))
        assertEquals("AI & APPS", PrivaCageDesign.navigationLabel("APP PRIVACY REVIEW & AI AUTOMATIONS"))
        assertEquals("AI", PrivaCageDesign.navigationLabel("AI PRIVACY AUTOMATIONS"))
        assertEquals("APP POLICIES", PrivaCageDesign.navigationLabel("APP POLICY REVIEW QUEUE"))
    }

    @Test
    fun onlyRoutineConfigurationActionsReceivePrimaryButtonStyling() {
        assertTrue(PrivaCageDesign.isPrimaryAction("Save configuration"))
        assertTrue(PrivaCageDesign.isPrimaryAction(" ENABLE DNS FILTERING "))
        assertTrue(PrivaCageDesign.isPrimaryAction("Save encrypted API token"))
        assertTrue(PrivaCageDesign.isPrimaryAction("Review supplied text"))
        assertFalse(PrivaCageDesign.isPrimaryAction("Stop DNS filtering"))
        assertFalse(PrivaCageDesign.isPrimaryAction("Clear local DNS event history"))
        assertFalse(PrivaCageDesign.isPrimaryAction("Confirm owner-key handoff complete"))
        assertFalse(PrivaCageDesign.isPrimaryAction(""))
        assertFalse(PrivaCageDesign.isPrimaryAction(null))
    }
}
