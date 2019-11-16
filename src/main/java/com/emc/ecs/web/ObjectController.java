package com.emc.ecs.web;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.iterable.S3Objects;
import com.amazonaws.services.s3.model.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.ArrayList;
import java.util.stream.Collectors;

@Controller
public class ObjectController {
    Log log = LogFactory.getLog(ObjectController.class);

    private static String ACCESS_KEY = "";
    private static String GOOD_USER = "";
    private static String SECRET_KEY = "";
    private static String ENDPOINT = "";
    private static String BUCKET = "";

    private static AWSCredentials credentials = new BasicAWSCredentials(ACCESS_KEY, SECRET_KEY);
    private static AWSCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(credentials);
    private static AwsClientBuilder.EndpointConfiguration endpointConfig = new AwsClientBuilder.EndpointConfiguration(
            ENDPOINT, Region.getRegion(Regions.DEFAULT_REGION).getName());
    private static AmazonS3 s3 = AmazonS3ClientBuilder
            .standard()
            .withEndpointConfiguration(endpointConfig)
            .withCredentials(credentialsProvider)
            .enablePathStyleAccess()
            .build();

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String index(Model model) {
        model.addAttribute("baduser", ACCESS_KEY);
        model.addAttribute("objects", list());
        return "index";
    }

    @RequestMapping(value = "/fix", method = RequestMethod.POST)
    public String fixme() {
        list().forEach(o -> {
            AccessControlList acl = s3.getObjectAcl(BUCKET, o.getKey());
            acl.grantPermission(new CanonicalGrantee(GOOD_USER), Permission.FullControl);
            s3.setObjectAcl(BUCKET, o.getKey(), acl);
        });
        return "redirect:/";
    }

    @RequestMapping(value="/fixall", method = RequestMethod.POST)
    public String fixAll() {
        ListObjectsV2Request req = new ListObjectsV2Request().withBucketName(BUCKET);
        ListObjectsV2Result listing;

        int pageNumber = 1;
        int recordsChanged =0;
        do {
            listing = s3.listObjectsV2(req);
            for (S3ObjectSummary objectSummary : listing.getObjectSummaries()) {
                S3Object o = new S3Object(objectSummary.getKey());
                try {
                    AccessControlList acl = s3.getObjectAcl(BUCKET, o.getKey());
                    acl.grantPermission(new CanonicalGrantee(GOOD_USER), Permission.FullControl);
                    s3.setObjectAcl(BUCKET, o.getKey(), acl);
                    recordsChanged++;
                } catch (AmazonS3Exception e) {
                    log.info(e);
                }
            }
            pageNumber++;
            log.info("Page Number: " + pageNumber);
            log.info(recordsChanged + " records changed");
            String token = listing.getNextContinuationToken();
            req.setContinuationToken(token);
        } while (listing.isTruncated());
        return "redirect:/";
    }

    private ArrayList<S3Object> list() {
        ArrayList<S3Object> objects = new ArrayList<>();
        ObjectListing listing = s3.listObjects(BUCKET);
        for (S3ObjectSummary objectSummary : listing.getObjectSummaries()) {
            S3Object o = new S3Object(objectSummary.getKey());
            try {
                AccessControlList acl = s3.getObjectAcl(BUCKET, objectSummary.getKey());
                Boolean bad = !acl.getGrantsAsList()
                        .stream()
                        .anyMatch(grant -> grant.getGrantee().getIdentifier().equals(GOOD_USER));
                String acls = acl.getGrantsAsList()
                        .stream()
                        .map(grant -> {
                            return grant.getGrantee().getIdentifier() +
                                    "/" +
                                    grant.getPermission().toString();
                        })
                        .collect(Collectors.joining(", "));
                o.setName(objectSummary.getKey());
                o.setDate(objectSummary.getLastModified());
                o.setAcls(acls);
                o.setBad(bad);
                objects.add(o);
            } catch (AmazonS3Exception e) {
                //log.info(e);
            }
        }
        return objects;
    }
}
