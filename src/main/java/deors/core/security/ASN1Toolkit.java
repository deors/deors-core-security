package deors.core.security;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 * Toolkit methods for parsing ASN.1 sequences.
 *
 * @author deors
 * @version 1.0
 */
final class ASN1Toolkit {

    /**
     * Code for the MD5 digest algorithm.
     */
    private static final String MD5_DIGEST_ALGORITHM = "md5"; //$NON-NLS-1$

    /**
     * Code for the SHA1 digest algorithm.
     */
    private static final String SHA1_DIGEST_ALGORITHM = "sha1"; //$NON-NLS-1$

    /**
     * Tag number for directoryName subject alternative name.
     */
    private static final Integer SUBJECT_ALT_NAMES_TAG_DIRECTORY_NAME = Integer.valueOf(4);

    /**
     * Default constructor. This class is a toolkit and therefore it cannot be instantiated.
     */
    private ASN1Toolkit() {
        super();
    }

    /**
     * Parses a DER sequence to obtain the CRL distribution points contained in it.
     *
     * @param derSequence the DER sequence containing distribution points information
     *
     * @return the CRL distribution points
     */
    static List<CRLDistributionPoint> parseCRLDistributionPoints(DERSequence derSequence) {

        List<CRLDistributionPoint> distributionPoints = new ArrayList<>();

        if (derSequence == null) {
            return distributionPoints;
        }

        for (int i = 0; i < derSequence.size(); i++) {

            ASN1Sequence asn1Sequence = (ASN1Sequence) derSequence.getObjectAt(i);

            distributionPoints.addAll(parseCRLDistributionPointsSection(asn1Sequence));
        }

        return distributionPoints;
    }

    /**
     * Parses a sequence containing distribution points information.
     *
     * @param asn1Sequence sequence containing distribution points information
     *
     * @return the CRL distribution points contained in the sequence
     */
    private static List<CRLDistributionPoint> parseCRLDistributionPointsSection(ASN1Sequence asn1Sequence) {

        final int tagFullName = 0;
        final int tagUniformResourceIdentifier = 6;
        final int tagDirectoryName = 4;

        List<CRLDistributionPoint> distPoints = new ArrayList<>();

        for (int j = 0; j < asn1Sequence.size(); j++) {

            ASN1TaggedObject tagged = (ASN1TaggedObject) asn1Sequence.getObjectAt(j);

            if (tagged.getTagNo() != tagFullName) {
                continue;
            }

            ASN1TaggedObject tagged1 = (ASN1TaggedObject) tagged.getObject();
            ASN1TaggedObject tagged2 = (ASN1TaggedObject) tagged1.getObject();

            if (tagged2.getTagNo() == tagUniformResourceIdentifier) {

                distPoints.add(parseCRLinURL(tagged2));

            } else if (tagged2.getTagNo() == tagDirectoryName) {

                distPoints.add(parseCRLinDirectory(tagged2));
            }
        }

        return distPoints;
    }

    /**
     * Parses an object containing CRL in URL information.
     *
     * @param asn1Object the object
     *
     * @return the CRL distribution point
     */
    private static CRLDistributionPoint parseCRLinURL(ASN1TaggedObject asn1Object) {

        int type;
        String location;
        DEROctetString tagOct = (DEROctetString) asn1Object.getObject();

        byte[] tagOctects = tagOct.getOctets();

        DERIA5String ia5String = new DERIA5String(tagOctects);

        type = CRLDistributionPoint.CRL_IN_URL;
        location = ia5String.getString();

        return new CRLDistributionPoint(type, location);
    }

    /**
     * Parses an object containing CRL in X.500 directory information.
     *
     * @param asn1Object the object
     *
     * @return the CRL distribution point
     */
    private static CRLDistributionPoint parseCRLinDirectory(ASN1TaggedObject asn1Object) {

        final char comma = ',';
        final char equals = '=';

        int type;
        String location;
        DERSequence tagSeq = (DERSequence) asn1Object.getObject();

        StringBuilder sb = new StringBuilder();

        // we change the ordering of the tokens (from cn to c)
        for (int k = tagSeq.size() - 1; k >= 0; k--) {

            DERSet tagSeqSet = (DERSet) tagSeq.getObjectAt(k);

            for (int l = 0; l < tagSeqSet.size(); l++) {

                DERSequence tagSeqSetSeq = (DERSequence) tagSeqSet.getObjectAt(l);
                Object o = tagSeqSetSeq.getObjectAt(1);

                DERObjectIdentifier oid =
                    (DERObjectIdentifier) tagSeqSetSeq.getObjectAt(0);

                String oidName = oid.getId();
                String oidValue = null;

                if (o instanceof DERPrintableString) {

                    DERPrintableString str =
                        (DERPrintableString) tagSeqSetSeq.getObjectAt(1);
                    oidValue = str.getString();

                } else if (o instanceof DERT61String) {

                    DERT61String str = (DERT61String) tagSeqSetSeq.getObjectAt(1);
                    oidValue = str.getString();

                } else {
                    continue;
                }

                if (sb.length() != 0) {
                    sb.append(comma);
                }

                sb.append(oidName);
                sb.append(equals);
                sb.append(oidValue);
            }
        }

        type = CRLDistributionPoint.CRL_IN_X500;
        location = sb.toString();

        return new CRLDistributionPoint(type, location);
    }

    /**
     * Parses a DER sequence to obtain the subject alternative names contained in it.
     *
     * @param derSequence the DER sequence containing subject alternative names
     *
     * @return the subject alternative names
     */
    static Map<Integer, Map<String, String>> parseSubjectAlternativeNames(DERSequence derSequence) {

        Map<Integer, Map<String, String>> tags = new HashMap<>();

        for (int i = 0; i < derSequence.size(); i++) {

            DERTaggedObject asn1Object = (DERTaggedObject) derSequence.getObjectAt(i);

            Integer tagNumber = Integer.valueOf(asn1Object.getTagNo());

            tags.put(tagNumber, parseNameEntry(asn1Object));
        }

        return tags;
    }

    /**
     * Parses a name entry.
     *
     * @param asn1Object the object
     *
     * @return map with the subject alternative names contained in the entry
     */
    private static Map<String, String> parseNameEntry(DERTaggedObject asn1Object) {

        Map<String, String> tagData = new HashMap<>();

        if (asn1Object.getObject() instanceof DEROctetString) {

            DEROctetString tagOctetString = (DEROctetString) asn1Object.getObject();

            String value = new String(tagOctetString.getOctets());
            tagData.put(value, value);

        } else if (asn1Object.getObject() instanceof DERSequence) {

            DERSequence tagSeq = (DERSequence) asn1Object.getObject();

            for (int j = 0; j < tagSeq.size(); j++) {

                if (tagSeq.getObjectAt(j) instanceof DERObjectIdentifier) {

                    DERObjectIdentifier oid = (DERObjectIdentifier) tagSeq.getObjectAt(j);
                    String oidName = oid.getId();

                    if (j + 1 < tagSeq.size()) {

                        DERTaggedObject tag = (DERTaggedObject) tagSeq.getObjectAt(j + 1);
                        Object o = tag.getObject();

                        if (o instanceof DERPrintableString) {

                            DERPrintableString str = (DERPrintableString) o;
                            tagData.put(oidName, str.getString());

                        } else if (o instanceof DERT61String) {

                            DERT61String str = (DERT61String) o;
                            tagData.put(oidName, str.getString());

                        } else if (o instanceof DERUTF8String) {

                            DERUTF8String str = (DERUTF8String) o;
                            tagData.put(oidName, str.getString());

                        } else if (o instanceof DEROctetString) {

                            DEROctetString str = (DEROctetString) o;
                            tagData.put(oidName, new String(str.getOctets()));

                        } else {
                            continue;
                        }
                    }
                } else if (tagSeq.getObjectAt(j) instanceof DERSet) {

                    DERSet set = (DERSet) tagSeq.getObjectAt(j);

                    for (int k = 0; k < set.size(); k++) {

                        DERSequence seq = (DERSequence) set.getObjectAt(k);
                        Object o = seq.getObjectAt(1);

                        DERObjectIdentifier oid = (DERObjectIdentifier) seq.getObjectAt(0);
                        String oidName = oid.getId();

                        if (o instanceof DERPrintableString) {

                            DERPrintableString str = (DERPrintableString) o;
                            tagData.put(oidName, str.getString());

                        } else if (o instanceof DERT61String) {

                            DERT61String str = (DERT61String) o;
                            tagData.put(oidName, str.getString());

                        } else if (o instanceof DERUTF8String) {

                            DERUTF8String str = (DERUTF8String) o;
                            tagData.put(oidName, str.getString());

                        } else if (o instanceof DEROctetString) {

                            DEROctetString str = (DEROctetString) o;
                            tagData.put(oidName, new String(str.getOctets()));

                        } else {
                            continue;
                        }
                    }
                } else {
                    continue;
                }
            }
        }

        return tagData;
    }

    /**
     * Parses a DER sequence to obtain the subject directory name contained in it.
     *
     * @param mainSeq the main sequence
     *
     * @return the subject directory name
     */
    public static Map<String, String> parseSubjectDirectoryName(DERSequence mainSeq) {

        final int tagDirectoryName = SUBJECT_ALT_NAMES_TAG_DIRECTORY_NAME.intValue();

        for (int i = 0; i < mainSeq.size(); i++) {

            DERTaggedObject tagged = (DERTaggedObject) mainSeq.getObjectAt(i);

            if (tagged.getTagNo() != tagDirectoryName) {
                continue;
            }

            DERSequence tagSeq = (DERSequence) tagged.getObject();

            Map<String, String> tagData = new HashMap<String, String>();

            for (int j = 0; j < tagSeq.size(); j++) {

                DERSet set = (DERSet) tagSeq.getObjectAt(j);

                for (int k = 0; k < set.size(); k++) {

                    DERSequence seq = (DERSequence) set.getObjectAt(k);
                    Object o = seq.getObjectAt(1);

                    DERObjectIdentifier oid = (DERObjectIdentifier) seq.getObjectAt(0);
                    String oidName = oid.getId();

                    if (o instanceof DERPrintableString) {

                        DERPrintableString str = (DERPrintableString) o;
                        tagData.put(oidName, str.getString());

                    } else if (o instanceof DERT61String) {

                        DERT61String str = (DERT61String) o;
                        tagData.put(oidName, str.getString());

                    } else if (o instanceof DERUTF8String) {

                        DERUTF8String str = (DERUTF8String) o;
                        tagData.put(oidName, str.getString());

                    } else if (o instanceof DEROctetString) {

                        DEROctetString str = (DEROctetString) o;
                        tagData.put(oidName, new String(str.getOctets()));

                    } else {
                        continue;
                    }
                }
            }

            return tagData;
        }

        // the tag directoryName was not found
        return null;
    }

    /**
     * Creates an ASN.1 signature.
     *
     * @param hash the hash of the data to be signed
     * @param hashingAlgorithm the hashing algorithm used to create the given hash
     *
     * @return the ASN.1 signature
     *
     * @throws java.io.IOException an I/O exception
     * @throws IllegalArgumentException the hash algorithm requested is not valid
     */
    static byte[] createASN1Signature(byte[] hash, String hashingAlgorithm)
        throws java.io.IOException {

        ASN1EncodableVector idSeq = new ASN1EncodableVector();

        if (hashingAlgorithm.equals(MD5_DIGEST_ALGORITHM)) {
            idSeq.add(new DERObjectIdentifier(CMSSignedDataGenerator.DIGEST_MD5));
        } else if (hashingAlgorithm.equals(SHA1_DIGEST_ALGORITHM)) {
            idSeq.add(new DERObjectIdentifier(CMSSignedDataGenerator.DIGEST_SHA1));
        } else {
            throw new IllegalArgumentException(SecurityContext.getMessage("CRYPTO_ERR_INVALID_HASH")); //$NON-NLS-1$
        }

        idSeq.add(new DERNull());

        ASN1EncodableVector mainSeq = new ASN1EncodableVector();
        mainSeq.add(new DERSequence(idSeq));
        mainSeq.add(new DEROctetString(hash));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream a1os = null;

        try {
            a1os = new ASN1OutputStream(baos);
            a1os.writeObject(new DERSequence(mainSeq));
            return baos.toByteArray();
        } finally {
            if (a1os != null) {
                a1os.close();
            }
        }

    }
}
