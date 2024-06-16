safe_list = [
    'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',"google.com", "wikipedia.org", "amazon.com", "github.com", "microsoft.com", "youtube.com", "bbc.com", "nytimes.com",
"coursera.org", "stackoverflow.com", "deepai.org", "spotify.com", "slack.com", "zoom.us", "cloudflare.com", "godaddy.com",
"bbc.com", "cnn.com", "theguardian.com", "forbes.com", "bloomberg.com", "wsj.com", "nationalgeographic.com",
"weather.com", "airbnb.com", "uber.com", "lyft.com", "booking.com", "expedia.com", "tripadvisor.com", "nike.com",
"adidas.com", "zara.com", "hnenterprise.com", "sephora.com", "macys.com", "walmart.com", "target.com", "costco.com",
"bestbuy.com", "homedepot.com", "lowes.com", "ikea.com", "wholefoodsmarket.com", "walgreens.com", "cvs.com", "samsung.com",
"sony.com", "dell.com", "hp.com", "asus.com", "lenovo.com", "acer.com", "msi.com",
"razer.com", "logitech.com", "autodesk.com", "sketchup.com", "blender.org", "zendesk.com", "freshdesk.com", "trello.com",
"asana.com", "jira.com", "bitbucket.org", "toggl.com", "hubspot.com", "mailchimp.com", "constantcontact.com", "activecampaign.com",
"getresponse.com", "aweber.com", "sendinblue.com", "zoho.com", "kaggle.com", "smartsheet.com", "clickup.com", "wrike.com",
"basecamp.com", "notion.so", "evernote.com", "onenote.com", "todoist.com", "ticktick.com", "habitica.com", "toggl.com",
"rescuetime.com", "myhours.com", "clockify.me", "timecamp.com", "harvestapp.com", "freckle.com", "hourstack.com", "timedoctor.com",
"hubstaff.com", "paymoapp.com", "tickspot.com", "payscale.com", "glassdoor.com", "indeed.com", "monster.com", "ziprecruiter.com",
"angel.co", "linkedin.com/jobs", "simplyhired.com", "careerbuilder.com", "dice.com", "hired.com", "thebalancecareers.com", "roberthalf.com",
"randstadusa.com", "adeccousa.com", "kellyservices.us", "manpower.com", "expresspros.com", "careerarc.com", "snagajob.com", "wayup.com",
"collegegrad.com", "internships.com", "govtjobs.com", "federaljobs.net", "usajobs.gov", "state.gov", "cityjobs.com", "countyjobs.com",
"districtjobs.com", "publicservicecareers.org", "teachercatapult.com", "educationamerica.net", "higheredjobs.com", "chroniclevitae.com", "k12jobspot.com", "academiccareers.com",
"employmentcrossing.com", "nationjob.com", "jobbankusa.com", "jobhero.com", "jobfox.com", "job-hunt.org", "localwise.com", "meetup.com",
"eventbrite.com", "tickettailor.com", "peerspace.com", "breather.com", "wework.com", "regus.com", "knotel.com", "convene.com",
"industriousoffice.com", "davincivirtual.com", "opusoffices.com", "cloudvo.com", "liquidspace.com", "croissant.io", "workfrom.co", "workbar.com",
"serendipitylabs.com", "workthere.com", "servcorp.com", "spacesworks.com", "coworker.com", "coworkingresources.org", "workspot.com", "maple.com",
"robinpowered.com", "eden.io", "officeotp.com", "birdoffice.com", "optixapp.com", "deskpass.com", "myhq.in", "hubblehq.com",
"baremetrics.com", "chartmogul.com", "profitwell.com", "clientbooks.com", "pulseapp.com", "bill.com", "xero.com", "quickbooks.intuit.com",
"freshbooks.com", "waveapps.com", "sage.com", "kashoo.com", "outright.com", "freeagent.com", "zipbooks.com", "zoho.com/books",
"lessaccounting.com", "invoiceninja.com", "and.co", "bokio.co.uk", "invoicehome.com", "invoiceberry.com", "invoice2go.com", "simpleinvoices.com",
"sliqtools.co.uk", "free-invoice.co.uk", "streetinvoice.com", "invoicely.com", "cashboardapp.com", "getharvest.com", "timecamp.com", "toggl.com",
"myhours.com", "clockify.me", "hubstaff.com", "worksnaps.net", "workpuls.com", "desktime.com", "paymoapp.com", "timewatch.com",
"tsheets.com", "timedoctor.com", "rescuetime.com", "timeular.com", "teamwork.com", "asana.com", "monday.com", "wrike.com",
"clickup.com", "notion.so", "trello.com", "basecamp.com", "smartsheet.com", "airtable.com", "qube-os.com", "flow.com",
"getflow.com", "teamgantt.com", "goodday.work", "proofhub.com", "taskworld.com", "azendoo.com", "projectplace.com", "mavenlink.com",
"nutcache.com", "redbooth.com", "scoro.com", "kanbanflow.com", "kanbanchi.com", "taskque.com", "workzone.com", "clarizen.com",
"liquidplanner.com", "workfront.com", "targetprocess.com", "daptiv.com", "projectinsight.net", "functionfox.com", "projectmanager.com", "project-open.com",
"ganttpro.com", "easyprojects.net", "sciforma.com", "bigtime.net", "teamworkpm.net", "celoxis.com", "appfluence.com", "prioritymatrix.com",
"viewpath.com", "rindle.com", "hey.space", "volerro.com", "activecollab.com", "taskade.com", "glasscubes.com", "plan.io",
"clockodo.com", "intervals.com", "breeze.pm", "planzone.com", "bubbl.us", "mindmeister.com", "coggle.it", "xmind.net",
"mindmup.com", "thebrain.com", "stormboard.com", "popplet.com", "mindomo.com", "simplemind.eu", "mindlyapp.com", "freemind.sourceforge.net",
"mindmapper.com", "mapul.com", "mindgenius.com", "inspiration.com", "conceptdraw.com", "creately.com", "smartdraw.com", "lucidchart.com",
"gliffy.com", "draw.io", "diagrams.net", "cacoo.com", "whimsical.com", "canva.com", "visme.co", "piktochart.com",
"venngage.com", "infogram.com", "easel.ly", "visualize.me", "adobe.com/products/illustrator", "coreldraw.com", "sketch.com", "affinity.serif.com",
"inkscape.org", "gravit.io", "vectornator.io", "vectr.com", "svg-edit.googlecode.com", "autodesk.com/products/autocad", "sketchup.com", "tinkercad.com",
"3ds.com", "blender.org", "freecadweb.org", "opencascade.com", "onshape.com", "fusion360.autodesk.com", "solidworks.com", "ironcad.com",
"rhino3d.com", "solidthinking.com", "siemens.com/software/solid-edge", "vectorworks.net", "bentley.com", "3d-coat.com", "mari.org", "keyshot.com",
"lumion.com", "unrealengine.com", "unity3d.com", "cryengine.com", "godotengine.org", "houdini.com", "marmoset.co", "substance3d.com",
"adobe.com/products/dimension", "zbrushcentral.com", "autodesk.com/products/maya", "pixologic.com", "maxon.net", "planetside.co.uk", "terragen.com", "world-machine.com",
"gaea.mydaxdev.com", "vue.bentley.com", "quixel.com", "megascans.se", "bridge.se", "mixer.se", "allegorithmic.com", "substance3d.com",
"x-normal.net", "knaldtech.com", "crazybump.com", "microsoft.com/pt-br/windows/photos", "adobe.com/products/photoshop", "gimp.org", "krita.org", "paint.com","hackthebox.com"
]