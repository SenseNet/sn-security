﻿using System.Diagnostics;
// ReSharper disable UnusedMember.Global

namespace SenseNet.Security.Tests.TestPortal
{
    [DebuggerDisplay("{Index}:{Name}:'{Mask}'")]
    public class PermissionType : PermissionTypeBase
    {
        public PermissionType(string name, int index) : base(name, index) { }

        /// <summary>Index = 0</summary>
        public static readonly PermissionType See = new PermissionType("See", 0);
        /// <summary>Index = 1</summary>
        public static readonly PermissionType Preview = new PermissionType("Preview", 1);
        /// <summary>Index = 2</summary>
        public static readonly PermissionType PreviewWithoutWatermark = new PermissionType("PreviewWithoutWatermark", 2);
        /// <summary>Index = 3</summary>
        public static readonly PermissionType PreviewWithoutRedaction = new PermissionType("PreviewWithoutRedaction", 3);
        /// <summary>Index = 4</summary>
        public static readonly PermissionType Open = new PermissionType("Open", 4);
        /// <summary>Index = 5</summary>
        public static readonly PermissionType OpenMinor = new PermissionType("OpenMinor", 5);
        /// <summary>Index = 6</summary>
        public static readonly PermissionType Save = new PermissionType("Save", 6);
        /// <summary>Index = 7</summary>
        public static readonly PermissionType Publish = new PermissionType("Publish", 7);
        /// <summary>Index = 8</summary>
        public static readonly PermissionType ForceCheckIn = new PermissionType("ForceCheckIn", 8);
        /// <summary>Index = 9</summary>
        public static readonly PermissionType AddNew = new PermissionType("AddNew", 9);
        /// <summary>Index = 10</summary>
        public static readonly PermissionType Approve = new PermissionType("Approve", 10);
        /// <summary>Index = 11</summary>
        public static readonly PermissionType Delete = new PermissionType("Delete", 11);
        /// <summary>Index = 12</summary>
        public static readonly PermissionType RecallOldVersion = new PermissionType("RecallOldVersion", 12);
        /// <summary>Index = 13</summary>
        public static readonly PermissionType DeleteOldVersion = new PermissionType("DeleteOldVersion", 13);
        /// <summary>Index = 14</summary>
        public static readonly PermissionType SeePermissions = new PermissionType("SeePermissions", 14);
        /// <summary>Index = 15</summary>
        public static readonly PermissionType SetPermissions = new PermissionType("SetPermissions", 15);
        /// <summary>Index = 16</summary>
        public static readonly PermissionType RunApplication = new PermissionType("RunApplication", 16);
        /// <summary>Index = 17</summary>
        public static readonly PermissionType ManageListsAndWorkspaces = new PermissionType("ManageListsAndWorkspaces", 17);
        /// <summary>Index = 18</summary>
        public static readonly PermissionType TakeOwnership = new PermissionType("TakeOwnership", 18);
        /// <summary>Index = 19</summary>
        public static readonly PermissionType Unused13 = new PermissionType("Unused13", 19);
        /// <summary>Index = 20</summary>
        public static readonly PermissionType Unused12 = new PermissionType("Unused12", 20);
        /// <summary>Index = 21</summary>
        public static readonly PermissionType Unused11 = new PermissionType("Unused11", 21);
        /// <summary>Index = 22</summary>
        public static readonly PermissionType Unused10 = new PermissionType("Unused10", 22);
        /// <summary>Index = 23</summary>
        public static readonly PermissionType Unused09 = new PermissionType("Unused09", 23);
        /// <summary>Index = 24</summary>
        public static readonly PermissionType Unused08 = new PermissionType("Unused08", 24);
        /// <summary>Index = 25</summary>
        public static readonly PermissionType Unused07 = new PermissionType("Unused07", 25);
        /// <summary>Index = 26</summary>
        public static readonly PermissionType Unused06 = new PermissionType("Unused06", 26);
        /// <summary>Index = 27</summary>
        public static readonly PermissionType Unused05 = new PermissionType("Unused05", 27);
        /// <summary>Index = 28</summary>
        public static readonly PermissionType Unused04 = new PermissionType("Unused04", 28);
        /// <summary>Index = 29</summary>
        public static readonly PermissionType Unused03 = new PermissionType("Unused03", 29);
        /// <summary>Index = 30</summary>
        public static readonly PermissionType Unused02 = new PermissionType("Unused02", 30);
        /// <summary>Index = 31</summary>
        public static readonly PermissionType Unused01 = new PermissionType("Unused01", 31);

        /// <summary>Index = 32</summary>
        public static readonly PermissionType Custom01 = new PermissionType("Custom01", 32);
        /// <summary>Index = 33</summary>
        public static readonly PermissionType Custom02 = new PermissionType("Custom02", 33);
        /// <summary>Index = 34</summary>
        public static readonly PermissionType Custom03 = new PermissionType("Custom03", 34);
        /// <summary>Index = 35</summary>
        public static readonly PermissionType Custom04 = new PermissionType("Custom04", 35);
        /// <summary>Index = 36</summary>
        public static readonly PermissionType Custom05 = new PermissionType("Custom05", 36);
        /// <summary>Index = 37</summary>
        public static readonly PermissionType Custom06 = new PermissionType("Custom06", 37);
        /// <summary>Index = 38</summary>
        public static readonly PermissionType Custom07 = new PermissionType("Custom07", 38);
        /// <summary>Index = 39</summary>
        public static readonly PermissionType Custom08 = new PermissionType("Custom08", 39);
        /// <summary>Index = 40</summary>
        public static readonly PermissionType Custom09 = new PermissionType("Custom09", 40);
        /// <summary>Index = 41</summary>
        public static readonly PermissionType Custom10 = new PermissionType("Custom10", 41);
        /// <summary>Index = 42</summary>
        public static readonly PermissionType Custom11 = new PermissionType("Custom11", 42);
        /// <summary>Index = 43</summary>
        public static readonly PermissionType Custom12 = new PermissionType("Custom12", 43);
        /// <summary>Index = 44</summary>
        public static readonly PermissionType Custom13 = new PermissionType("Custom13", 44);
        /// <summary>Index = 45</summary>
        public static readonly PermissionType Custom14 = new PermissionType("Custom14", 45);
        /// <summary>Index = 46</summary>
        public static readonly PermissionType Custom15 = new PermissionType("Custom15", 46);
        /// <summary>Index = 47</summary>
        public static readonly PermissionType Custom16 = new PermissionType("Custom16", 47);
        /// <summary>Index = 48</summary>
        public static readonly PermissionType Custom17 = new PermissionType("Custom17", 48);
        /// <summary>Index = 49</summary>
        public static readonly PermissionType Custom18 = new PermissionType("Custom18", 49);
        /// <summary>Index = 50</summary>
        public static readonly PermissionType Custom19 = new PermissionType("Custom19", 50);
        /// <summary>Index = 51</summary>
        public static readonly PermissionType Custom20 = new PermissionType("Custom20", 51);
        /// <summary>Index = 52</summary>
        public static readonly PermissionType Custom21 = new PermissionType("Custom21", 52);
        /// <summary>Index = 53</summary>
        public static readonly PermissionType Custom22 = new PermissionType("Custom22", 53);
        /// <summary>Index = 54</summary>
        public static readonly PermissionType Custom23 = new PermissionType("Custom23", 54);
        /// <summary>Index = 55</summary>
        public static readonly PermissionType Custom24 = new PermissionType("Custom24", 55);
        /// <summary>Index = 56</summary>
        public static readonly PermissionType Custom25 = new PermissionType("Custom25", 56);
        /// <summary>Index = 57</summary>
        public static readonly PermissionType Custom26 = new PermissionType("Custom26", 57);
        /// <summary>Index = 58</summary>
        public static readonly PermissionType Custom27 = new PermissionType("Custom27", 58);
        /// <summary>Index = 59</summary>
        public static readonly PermissionType Custom28 = new PermissionType("Custom28", 59);
        /// <summary>Index = 60</summary>
        public static readonly PermissionType Custom29 = new PermissionType("Custom29", 60);
        /// <summary>Index = 61</summary>
        public static readonly PermissionType Custom30 = new PermissionType("Custom30", 61);
        /// <summary>Index = 62</summary>
        public static readonly PermissionType Custom31 = new PermissionType("Custom31", 62);
        /// <summary>Index = 63</summary>
        public static readonly PermissionType Custom32 = new PermissionType("Custom32", 63);

    }
}
