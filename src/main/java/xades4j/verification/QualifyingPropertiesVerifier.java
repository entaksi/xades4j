/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.verification;

import java.util.Collection;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.PropertyDataStructureException;

/**
 *
 * @author Luís
 */
interface QualifyingPropertiesVerifier
{
    /**
     * Verifies the data objects' structure and the XAdES rules.
     */
    Collection<PropertyInfo> verifyProperties(
            Collection<PropertyDataObject> unmarshalledProperties,
            QualifyingPropertyVerificationContext ctx) throws PropertyDataStructureException, InvalidPropertyException, QualifyingPropertyVerifierNotAvailableException;
}
