package deors.core.security;

import static deors.core.security.CryptoToolkit.MD5_HASHING_ALGORITHM;
import static deors.core.security.CryptoToolkit.SHA1_HASHING_ALGORITHM;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 * Toolkit methods for parsing ASN.1 sequences.
 *
 * @author deors
 * @version 1.0
 */
final class ASN1Toolkit {

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
     * Parses an ASN.1 sequence to obtain the CRL distribution points contained in it.
     *
     * @param asn1Sequence the ASN.1 sequence containing distribution points information
     *
     * @return the CRL distribution points
     */
    static List<CRLDistributionPoint> parseCRLDistributionPoints(ASN1Sequence asn1Sequence) {

        List<CRLDistributionPoint> distributionPoints = new ArrayList<>();

        if (asn1Sequence == null) {
            return distributionPoints;
        }

        for (int i = 0; i < asn1Sequence.size(); i++) {

            ASN1Sequence asn1SectionSequence = (ASN1Sequence) asn1Sequence.getObjectAt(i);

            distributionPoints.addAll(parseCRLDistributionPointsSection(asn1SectionSequence));
        }

        return distributionPoints;
    }

    /**
     * Parses an ASN.1 sequence containing distribution points information.
     *
     * @param asn1Sequence the ASN.1 sequence containing distribution points information
     *
     * @return the CRL distribution points contained in the sequence
     */
    private static List<CRLDistributionPoint> parseCRLDistributionPointsSection(ASN1Sequence asn1Sequence) {

        final int tagFullName = 0;
        final int tagUniformResourceIdentifier = 6;
        final int tagDirectoryName = 4;

        List<CRLDistributionPoint> distributionPoints = new ArrayList<>();

        for (int i = 0; i < asn1Sequence.size(); i++) {

            ASN1TaggedObject seqElem = (ASN1TaggedObject) asn1Sequence.getObjectAt(i);

            if (seqElem.getTagNo() != tagFullName) {
                continue;
            }

            ASN1TaggedObject seqElemBaseObj = (ASN1TaggedObject) seqElem.getBaseObject();
            ASN1Sequence nestedSeq = (ASN1Sequence) seqElemBaseObj.getBaseObject();

            for (int j = 0; j < nestedSeq.size(); j++) {
                ASN1TaggedObject nestedSeqElem =
                    (ASN1TaggedObject) nestedSeq.getObjectAt(j);

                if (nestedSeqElem.getTagNo() == tagUniformResourceIdentifier) {

                    distributionPoints.add(parseCRLinURL(nestedSeqElem));

                } else if (nestedSeqElem.getTagNo() == tagDirectoryName) {

                    distributionPoints.add(parseCRLinDirectory(nestedSeqElem));
                }
            }
        }

        return distributionPoints;
    }

    /**
     * Parses an ASN.1 tagged object containing CRL in URL information.
     *
     * @param asn1Object the ASN.1 tagged object
     *
     * @return the CRL distribution point
     */
    private static CRLDistributionPoint parseCRLinURL(ASN1TaggedObject asn1Object) {

        int type;
        String location;
        DEROctetString tagOct = (DEROctetString) asn1Object.getBaseObject();

        byte[] tagOctects = tagOct.getOctets();

        DERIA5String ia5String = new DERIA5String(new String(tagOctects));

        type = CRLDistributionPoint.CRL_IN_URL;
        location = ia5String.getString();

        return new CRLDistributionPoint(type, location);
    }

    /**
     * Parses an ASN.1 tagged object containing CRL in X.500 directory information.
     *
     * @param asn1Object the ASN.1 tagged object
     *
     * @return the CRL distribution point
     */
    private static CRLDistributionPoint parseCRLinDirectory(ASN1TaggedObject asn1Object) {

        final char comma = ',';
        final char equals = '=';

        int type;
        String location;
        ASN1Sequence tagSeq = (ASN1Sequence) asn1Object.getBaseObject();

        StringBuilder sb = new StringBuilder();

        // we change the ordering of the tokens (from cn to c)
        for (int k = tagSeq.size() - 1; k >= 0; k--) {

            DERSet tagSeqSet = (DERSet) tagSeq.getObjectAt(k);

            for (int l = 0; l < tagSeqSet.size(); l++) {

                ASN1Sequence tagSeqSetSeq = (ASN1Sequence) tagSeqSet.getObjectAt(l);
                Object o = tagSeqSetSeq.getObjectAt(1);

                ASN1ObjectIdentifier oid =
                    (ASN1ObjectIdentifier) tagSeqSetSeq.getObjectAt(0);

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
     * Parses an ASN.1 sequence to obtain the subject alternative names contained in it.
     *
     * @param asn1Sequence the ASN.1 sequence containing subject alternative names
     *
     * @return the subject alternative names
     */
    static Map<Integer, Map<String, String>> parseSubjectAlternativeNames(ASN1Sequence asn1Sequence) {

        Map<Integer, Map<String, String>> tags = new HashMap<>();

        for (int i = 0; i < asn1Sequence.size(); i++) {

            ASN1Encodable asn1Object = asn1Sequence.getObjectAt(i);

            if (asn1Object instanceof DERTaggedObject) {

                DERTaggedObject taggedObject = (DERTaggedObject) asn1Object;

                Integer tagNumber = Integer.valueOf(taggedObject.getTagNo());

                tags.put(tagNumber, parseNameEntry(taggedObject));

            } else if (asn1Object instanceof DLTaggedObject) {

                DLTaggedObject taggedObject = (DLTaggedObject) asn1Object;

                Integer tagNumber = Integer.valueOf(taggedObject.getTagNo());

                tags.put(tagNumber, parseNameEntry(taggedObject));
            }
        }

        return tags;
    }

    /**
     * Parses an ASN.1 tagged object holding information for a name entry.
     *
     * @param asn1Object the ASN.1 tagged object
     *
     * @return map with the subject alternative names contained in the entry
     */
    private static Map<String, String> parseNameEntry(ASN1TaggedObject asn1Object) {

        Map<String, String> tagData = new HashMap<>();

        if (asn1Object.getBaseObject() instanceof DEROctetString) {

            DEROctetString tagOctetString = (DEROctetString) asn1Object.getBaseObject();

            String value = new String(tagOctetString.getOctets());
            tagData.put(value, value);

        } else if (asn1Object.getBaseObject() instanceof ASN1Sequence) {

            ASN1Sequence tagSeq = (ASN1Sequence) asn1Object.getBaseObject();

            for (int j = 0; j < tagSeq.size(); j++) {

                if (tagSeq.getObjectAt(j) instanceof ASN1ObjectIdentifier) {

                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) tagSeq.getObjectAt(j);
                    String oidName = oid.getId();

                    if (j + 1 < tagSeq.size() && tagSeq.getObjectAt(j + 1) instanceof DERTaggedObject) {

                        DERTaggedObject tag = (DERTaggedObject) tagSeq.getObjectAt(j + 1);
                        Object o = tag.getBaseObject();

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

                        ASN1Sequence seq = (ASN1Sequence) set.getObjectAt(k);
                        Object o = seq.getObjectAt(1);

                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq.getObjectAt(0);
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
                } else if (tagSeq.getObjectAt(j) instanceof DLSet) {

                    DLSet set = (DLSet) tagSeq.getObjectAt(j);

                    for (int k = 0; k < set.size(); k++) {

                        ASN1Sequence seq = (ASN1Sequence) set.getObjectAt(k);
                        Object o = seq.getObjectAt(1);

                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq.getObjectAt(0);
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
     * Parses an ASN.1 sequence to obtain the subject directory name contained in it.
     *
     * @param asn1Sequence the ASN.1 sequence
     *
     * @return the subject directory name
     */
    static Map<String, String> parseSubjectDirectoryName(ASN1Sequence asn1Sequence) {

        final int tagDirectoryName = SUBJECT_ALT_NAMES_TAG_DIRECTORY_NAME.intValue();

        Map<String, String> tagData = new HashMap<String, String>();

        for (int i = 0; i < asn1Sequence.size(); i++) {

            if (asn1Sequence.getObjectAt(i) instanceof DERTaggedObject) {

                DERTaggedObject tagged = (DERTaggedObject) asn1Sequence.getObjectAt(i);

                if (tagged.getTagNo() != tagDirectoryName) {
                    continue;
                }

                ASN1Sequence tagSeq = (ASN1Sequence) tagged.getBaseObject();

                for (int j = 0; j < tagSeq.size(); j++) {

                    DERSet set = (DERSet) tagSeq.getObjectAt(j);

                    for (int k = 0; k < set.size(); k++) {

                        ASN1Sequence seq = (ASN1Sequence) set.getObjectAt(k);
                        Object o = seq.getObjectAt(1);

                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq.getObjectAt(0);
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
            } else if (asn1Sequence.getObjectAt(i) instanceof DLTaggedObject) {
                
                DLTaggedObject tagged = (DLTaggedObject) asn1Sequence.getObjectAt(i);

                if (tagged.getTagNo() != tagDirectoryName) {
                    continue;
                }

                ASN1Sequence tagSeq = (ASN1Sequence) tagged.getBaseObject();

                for (int j = 0; j < tagSeq.size(); j++) {

                    DLSet set = (DLSet) tagSeq.getObjectAt(j);

                    for (int k = 0; k < set.size(); k++) {

                        ASN1Sequence seq = (ASN1Sequence) set.getObjectAt(k);
                        Object o = seq.getObjectAt(1);

                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq.getObjectAt(0);
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
            }
        }

        return tagData;
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
     * @throws java.lang.IllegalArgumentException the hash algorithm requested is not valid
     */
    static byte[] createASN1Signature(byte[] hash, String hashingAlgorithm)
        throws java.io.IOException {

        ASN1EncodableVector idSeq = new ASN1EncodableVector();

        if (hashingAlgorithm.equals(MD5_HASHING_ALGORITHM)) {
            idSeq.add(new ASN1ObjectIdentifier(CMSSignedDataGenerator.DIGEST_MD5));
        } else if (hashingAlgorithm.equals(SHA1_HASHING_ALGORITHM)) {
            idSeq.add(new ASN1ObjectIdentifier(CMSSignedDataGenerator.DIGEST_SHA1));
        } else {
            throw new IllegalArgumentException(SecurityContext.getMessage("CRYPTO_ERR_INVALID_HASH")); //$NON-NLS-1$
        }

        idSeq.add(DERNull.INSTANCE);

        ASN1EncodableVector mainSeq = new ASN1EncodableVector();
        mainSeq.add(new DERSequence(idSeq));
        mainSeq.add(new DEROctetString(hash));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream a1os = null;

        try {
            a1os = ASN1OutputStream.create(baos);
            a1os.writeObject(new DERSequence(mainSeq));
            return baos.toByteArray();
        } finally {
            if (a1os != null) {
                a1os.close();
            }
        }

    }
}
